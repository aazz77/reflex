//! XHTTP（SplitHTTP）传输层：服务端与客户端对偶实现。


use anyhow::Result;
use bytes::{Buf, BytesMut, Bytes};
use http_body_util::{BodyExt, Empty, Full, StreamBody};
use hyper::{Method, Request, Response, StatusCode, Uri};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex, Notify};
use tokio_util::sync::PollSender;
use tracing::{debug, warn};
use std::future::Future;
use std::io;
use std::sync::atomic::Ordering;
use futures_util::StreamExt;
use hyper::body::{Frame, Incoming};
use hyper::header::{HeaderName, HeaderValue, HOST};
use hyper_util::client::legacy::Client;
use portable_atomic::AtomicI64;
use rand::Rng;
use tokio::net::TcpStream;
use tokio_stream::wrappers::ReceiverStream;
use tower::Service;
use uuid::Uuid;
use reflex_config::outbound::{TlsConfig, XhttpTransportConfig};
use reflex_common::outbound::{apply_mark_to_tcp, set_tcp_opts};

#[derive(Debug, Clone)]
pub struct XhttpServerOptions {
    pub path: String,
    pub host: Option<String>,
}

impl Default for XhttpServerOptions {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            host: None,
        }
    }
}

impl XhttpServerOptions {
    pub fn from_config(cfg: &reflex_config::inbound::InboundXhttpTransportConfig) -> Self {
        Self {
            path: cfg.path.clone(),
            host: cfg.host.clone(),
        }
    }

    /// 对齐 Xray `Config.GetNormalizedPath`（`splithttp/config.go`）：
    ///   - 空或非 `/` 开头 → 前补 `/`
    ///   - 末尾保证有 `/`（便于 `parse_path` 切 sessionId/seq）
    ///
    /// 注意 `/` 不能被规范化成 `//`（trim 后为空串 → 规范化为 `/`）。
    pub fn normalized_path(&self) -> String {
        let mut p = self.path.trim_end_matches('/').to_string();
        if !p.starts_with('/') {
            p.insert(0, '/');
        }
        if p.is_empty() {
            p.push('/');
        }
        if !p.ends_with('/') {
            p.push('/');
        }
        p
    }
}

// ── 上行数据包 ─────────────────────────────────────────────────────────────────

enum UploadPacket {
    Chunk(bytes::Bytes),
    Packet { seq: u64, data: bytes::Bytes },
    Eof,
}

// ── Session ───────────────────────────────────────────────────────────────────

struct Session {
    /// POST handler 写上行数据
    up_tx: mpsc::Sender<UploadPacket>,
    /// GET handler 到达时取走，构造 XhttpServerStream 的读端
    up_rx: Option<mpsc::Receiver<UploadPacket>>,
    /// XhttpServerStream 写端写下行数据。
    /// GET handler 到达时 take（不再 clone）：只有当所有 down_tx 都被释放后，
    /// down_rx 才会返回 None，GET 响应才会结束（否则下行连接挂死到 TTL）。
    down_tx: Option<mpsc::Sender<bytes::Bytes>>,
    /// GET handler 到达时取走，作为 response body
    down_rx: Option<mpsc::Receiver<bytes::Bytes>>,
    /// GET 到达通知（供 TTL 任务监听）
    get_arrived: Arc<Notify>,
}

// ── XhttpServer ───────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct XhttpServer {
    inner: Arc<ServerInner>,
}

struct ServerInner {
    cfg: XhttpServerOptions,
    sessions: Mutex<HashMap<String, Arc<Mutex<Session>>>>,
    ready_tx: mpsc::Sender<XhttpServerStream>,
    ready_rx: Mutex<mpsc::Receiver<XhttpServerStream>>,
}

impl XhttpServer {
    pub fn new(cfg: XhttpServerOptions) -> Self {
        let (ready_tx, ready_rx) = mpsc::channel(64);
        Self {
            inner: Arc::new(ServerInner {
                cfg,
                sessions: Mutex::new(HashMap::new()),
                ready_tx,
                ready_rx: Mutex::new(ready_rx),
            }),
        }
    }

    /// 等待下一个完整的 xhttp 逻辑连接就绪，返回 XhttpServerStream
    pub async fn accept(&self) -> Option<XhttpServerStream> {
        self.inner.ready_rx.lock().await.recv().await
    }

    /// 把一个已完成 TLS/Reality 握手的流交给 hyper（立即返回，不阻塞）
    pub fn feed_tls<S>(&self, stream: S, peer: SocketAddr)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            serve_conn(hyper_util::rt::TokioIo::new(stream), peer, inner).await;
        });
    }
}

// ── hyper 连接 ────────────────────────────────────────────────────────────────

async fn serve_conn<IO>(io: IO, peer: SocketAddr, inner: Arc<ServerInner>)
where
    IO: hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
{
    let svc = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
        let inner = Arc::clone(&inner);
        async move {
            let resp = handle_request(req, &inner, peer).await;
            Ok::<_, std::convert::Infallible>(resp)
        }
    });
    if let Err(e) =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
            .serve_connection(io, svc)
            .await
    {
        debug!("[xhttp] {peer} conn closed: {e}");
    }
}

// ── Session 管理 ───────────────────────────────────────────────────────────────

async fn get_or_create_session(inner: &Arc<ServerInner>, session_id: &str) -> Arc<Mutex<Session>> {
    let mut map = inner.sessions.lock().await;
    if let Some(s) = map.get(session_id) {
        return Arc::clone(s);
    }

    // 容量 512：packet-up 模式下客户端每个 chunk 一个 POST，
    // 高并发时容量太小会导致 up_tx.send() 阻塞占用 hyper 连接
    let (up_tx, up_rx) = mpsc::channel::<UploadPacket>(512);
    let (down_tx, down_rx) = mpsc::channel::<bytes::Bytes>(512);
    let get_arrived = Arc::new(Notify::new());

    let session = Arc::new(Mutex::new(Session {
        up_tx,
        up_rx: Some(up_rx),
        down_tx: Some(down_tx),
        down_rx: Some(down_rx),
        get_arrived: Arc::clone(&get_arrived),
    }));
    map.insert(session_id.to_string(), Arc::clone(&session));

    // TTL：30s 内 GET 未到则清理；GET 到达后由 ResponseBody cleanup 回调负责
    let inner2 = Arc::clone(inner);
    let sid = session_id.to_string();
    tokio::spawn(async move {
        let get_timed_out = tokio::time::timeout(Duration::from_secs(30), get_arrived.notified())
            .await
            .is_err();

        if get_timed_out {
            debug!("[xhttp] session {sid} TTL expired (no GET)");
            if let Some(s) = inner2.sessions.lock().await.remove(&sid) {
                let s = s.lock().await;
                let _ = s.up_tx.send(UploadPacket::Eof).await;
            }
        }
    });

    session
}

// ── 路径解析 ───────────────────────────────────────────────────────────────────

fn parse_path(req_path: &str, base_path: &str) -> Option<(Option<String>, Option<String>)> {
    let base_no_slash = base_path.trim_end_matches('/');

    let rest = if req_path == base_no_slash || req_path == base_path {
        ""
    } else {
        let s = req_path.strip_prefix(base_path)?;
        s.trim_start_matches('/')
    };

    if rest.is_empty() {
        return Some((None, None));
    }

    let mut parts = rest.splitn(2, '/');
    let session_id = parts.next().filter(|s| !s.is_empty()).map(str::to_string);
    let seq = parts.next().filter(|s| !s.is_empty()).map(str::to_string);
    Some((session_id, seq))
}

// ── HTTP 请求处理 ──────────────────────────────────────────────────────────────

/// 对齐 Xray `internet.IsValidHTTPHost`：大小写不敏感；带端口仅比较 host 部分
fn is_valid_http_host(request: &str, config: &str) -> bool {
    let r = request.to_lowercase();
    let c = config.to_lowercase();
    if let Some((h, _)) = r.rsplit_once(':') {
        // IPv6 字面量 `[::1]:443` → h="[::1]" 仍正确
        h == c
    } else {
        r == c
    }
}

async fn handle_request(
    req: Request<hyper::body::Incoming>,
    inner: &Arc<ServerInner>,
    peer: SocketAddr,
) -> Response<ResponseBody> {
    let origin = req
        .headers()
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    if let Some(expected) = &inner.cfg.host {
        let req_host = req
            .headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !is_valid_http_host(req_host, expected) {
            warn!("[xhttp] {peer} bad host: {req_host} != {expected}");
            return plain_with_cors(StatusCode::NOT_FOUND, origin.as_deref());
        }
    }

    if *req.method() == Method::OPTIONS {
        return cors_ok(origin.as_deref());
    }

    let base_path = inner.cfg.normalized_path();
    let req_path = req.uri().path().to_string();

    let (session_id, seq_str) = match parse_path(&req_path, &base_path) {
        Some(p) => p,
        None => {
            warn!("[xhttp] {peer} bad path: {req_path} (base={base_path})");
            return plain_with_cors(StatusCode::NOT_FOUND, origin.as_deref());
        }
    };

    debug!(
        "[xhttp] {peer} {} session={session_id:?} seq={seq_str:?}",
        req.method()
    );

    let is_downlink = *req.method() == Method::GET && seq_str.is_none();
    if is_downlink {
        handle_get(req, inner, session_id.as_deref(), peer, origin).await
    } else {
        handle_post(
            req,
            inner,
            session_id.as_deref(),
            seq_str.as_deref(),
            peer,
            origin,
        )
        .await
    }
}

/// GET handler：downlink 或 stream-one
async fn handle_get(
    req: Request<hyper::body::Incoming>,
    inner: &Arc<ServerInner>,
    session_id: Option<&str>,
    peer: SocketAddr,
    origin: Option<String>,
) -> Response<ResponseBody> {
    // ── stream-one：无 sessionId ────────────────────────────────────────────
    if session_id.is_none() {
        let (up_tx, up_rx) = mpsc::channel::<UploadPacket>(64);
        let (down_tx, down_rx) = mpsc::channel::<bytes::Bytes>(64);

        let mut body = req.into_body();
        tokio::spawn(async move {
            loop {
                match body.frame().await {
                    None => break,
                    Some(Ok(frame)) => {
                        if let Ok(data) = frame.into_data() {
                            if up_tx.send(UploadPacket::Chunk(data)).await.is_err() {
                                break;
                            }
                        }
                    }
                    Some(Err(e)) => {
                        debug!("[xhttp] {peer} stream-one up: {e}");
                        break;
                    }
                }
            }
            let _ = up_tx.send(UploadPacket::Eof).await;
        });

        let xhs = XhttpServerStream::new(up_rx, down_tx);
        let _ = inner.ready_tx.send(xhs).await;

        return downlink_response(down_rx, origin.as_deref(), None);
    }

    // ── stream-down：有 sessionId ───────────────────────────────────────────
    let sid = session_id.unwrap();
    let session_arc = get_or_create_session(inner, sid).await;
    let mut session = session_arc.lock().await;

    let up_rx = match session.up_rx.take() {
        Some(r) => r,
        None => {
            warn!("[xhttp] {peer} duplicate GET for session {sid}");
            return plain_with_cors(StatusCode::CONFLICT, origin.as_deref());
        }
    };
    let down_rx = match session.down_rx.take() {
        Some(r) => r,
        None => {
            warn!("[xhttp] {peer} down_rx already taken for session {sid}");
            return plain_with_cors(StatusCode::CONFLICT, origin.as_deref());
        }
    };
    // take（不是 clone）：XhttpServerStream 释放 down_tx 后所有 sender 消失，
    // down_rx 才会返回 None，GET 响应才能正常结束
    let down_tx = match session.down_tx.take() {
        Some(t) => t,
        None => {
            warn!("[xhttp] {peer} down_tx already taken for session {sid}");
            return plain_with_cors(StatusCode::CONFLICT, origin.as_deref());
        }
    };

    // 通知 TTL 任务：GET 已到达
    session.get_arrived.notify_one();
    drop(session);
    // 不从 map 移除 session：up_tx 留在 session 里，后续 POST 仍可拿到

    let xhs = XhttpServerStream::new(up_rx, down_tx);
    let _ = inner.ready_tx.send(xhs).await;

    // cleanup：GET 响应流结束时移除 session（对齐 Xray hub.go 的 defer delete）
    let inner_clone = Arc::clone(inner);
    let sid_owned = sid.to_string();
    let cleanup: Option<Box<dyn FnOnce() + Send + 'static>> = Some(Box::new(move || {
        tokio::spawn(async move {
            if let Some(s) = inner_clone.sessions.lock().await.remove(&sid_owned) {
                debug!("[xhttp] session removed on GET response end");
                let _ = s.lock().await.up_tx.send(UploadPacket::Eof).await;
            }
        });
    }));

    downlink_response(down_rx, origin.as_deref(), cleanup)
}

/// POST/PUT handler：接收上行数据
async fn handle_post(
    req: Request<hyper::body::Incoming>,
    inner: &Arc<ServerInner>,
    session_id: Option<&str>,
    seq_str: Option<&str>,
    peer: SocketAddr,
    origin: Option<String>,
) -> Response<ResponseBody> {
    let up_tx = if let Some(sid) = session_id {
        let session_arc = get_or_create_session(inner, sid).await;
        let session = session_arc.lock().await;
        session.up_tx.clone()
    } else {
        warn!("[xhttp] {peer} POST without sessionId");
        return plain_with_cors(StatusCode::BAD_REQUEST, origin.as_deref());
    };

    match seq_str {
        None => {
            // stream-up
            let mut body = req.into_body();
            tokio::spawn(async move {
                loop {
                    match body.frame().await {
                        None => break,
                        Some(Ok(frame)) => {
                            if let Ok(data) = frame.into_data() {
                                if up_tx.send(UploadPacket::Chunk(data)).await.is_err() {
                                    break;
                                }
                            }
                        }
                        Some(Err(e)) => {
                            debug!("[xhttp] stream-up: {e}");
                            break;
                        }
                    }
                }
                let _ = up_tx.send(UploadPacket::Eof).await;
            });
            // 对齐 Xray hub.go：stream-up 响应设置 X-Accel-Buffering / Cache-Control
            return stream_up_response(origin.as_deref());
        }
        Some(s) => {
            // packet-up：同步收完 body 再返回 200（否则 hyper 可能先处理下一个
            // pipelined 请求，破坏 HTTP/1.1 分帧）
            let seq: u64 = match s.parse() {
                Ok(n) => n,
                Err(_) => {
                    warn!("[xhttp] {peer} invalid seq: {s}");
                    return plain_with_cors(StatusCode::BAD_REQUEST, origin.as_deref());
                }
            };
            let body = req.into_body();
            let had_body = match body.collect().await {
                Ok(c) => {
                    let bytes = c.to_bytes();
                    let had = !bytes.is_empty();
                    let _ = up_tx
                        .send(UploadPacket::Packet { seq, data: bytes })
                        .await;
                    had
                }
                Err(e) => {
                    debug!("[xhttp] {peer} packet-up collect: {e}");
                    return plain_with_cors(StatusCode::BAD_REQUEST, origin.as_deref());
                }
            };
            // 对齐 Xray hub.go：无 body 的 POST 显式 no-store 防中间件缓存
            if !had_body {
                return packet_up_response_no_body(origin.as_deref());
            }
        }
    }

    plain_with_cors(StatusCode::OK, origin.as_deref())
}

/// 对齐 Xray `Config.WriteResponseHeader`：无 Origin → `*`；有 Origin → 回写
fn cors_origin_header(
    builder: http::response::Builder,
    origin: Option<&str>,
) -> http::response::Builder {
    match origin {
        Some(o) => builder
            .header("Access-Control-Allow-Origin", o)
            .header("Access-Control-Allow-Credentials", "true")
            .header("Vary", "Origin"),
        None => builder.header("Access-Control-Allow-Origin", "*"),
    }
}

fn downlink_response(
    down_rx: mpsc::Receiver<bytes::Bytes>,
    origin: Option<&str>,
    cleanup: Option<Box<dyn FnOnce() + Send + 'static>>,
) -> Response<ResponseBody> {
    let builder = Response::builder()
        .status(StatusCode::OK)
        // text/event-stream 让 nginx/CDN 关闭缓冲（对齐 Xray hub.go）
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-store")
        .header("X-Accel-Buffering", "no");
    let builder = cors_origin_header(builder, origin);
    builder
        .body(ResponseBody::Stream {
            rx: down_rx,
            cleanup,
        })
        .unwrap()
}

/// stream-up 响应
fn stream_up_response(origin: Option<&str>) -> Response<ResponseBody> {
    let builder = Response::builder()
        .status(StatusCode::OK)
        .header("X-Accel-Buffering", "no")
        .header("Cache-Control", "no-store");
    let builder = cors_origin_header(builder, origin);
    builder.body(ResponseBody::Empty).unwrap()
}

/// packet-up 无 body 响应
fn packet_up_response_no_body(origin: Option<&str>) -> Response<ResponseBody> {
    let builder = Response::builder()
        .status(StatusCode::OK)
        .header("Cache-Control", "no-store");
    let builder = cors_origin_header(builder, origin);
    builder.body(ResponseBody::Empty).unwrap()
}

fn plain_with_cors(code: StatusCode, origin: Option<&str>) -> Response<ResponseBody> {
    let builder = Response::builder().status(code);
    let builder = cors_origin_header(builder, origin);
    builder.body(ResponseBody::Empty).unwrap()
}

fn cors_ok(origin: Option<&str>) -> Response<ResponseBody> {
    let builder = Response::builder().status(StatusCode::OK);
    let builder = cors_origin_header(builder, origin);
    builder
        .header("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
        .header("Access-Control-Allow-Headers", "Content-Type")
        .body(ResponseBody::Empty)
        .unwrap()
}

// ── Response body ─────────────────────────────────────────────────────────────

enum ResponseBody {
    Empty,
    Stream {
        rx: mpsc::Receiver<bytes::Bytes>,
        /// 响应流结束（poll_frame 返回 None）时执行一次，清理 session
        cleanup: Option<Box<dyn FnOnce() + Send + 'static>>,
    },
}

impl http_body::Body for ResponseBody {
    type Data = bytes::Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            ResponseBody::Empty => Poll::Ready(None),
            ResponseBody::Stream { rx, cleanup } => match rx.poll_recv(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(None) => {
                    if let Some(c) = cleanup.take() {
                        c();
                    }
                    Poll::Ready(None)
                }
                Poll::Ready(Some(d)) => Poll::Ready(Some(Ok(http_body::Frame::data(d)))),
            },
        }
    }
}

// ── XhttpServerStream ───────────────────────────────────────────────────────────────

struct PktQueue {
    heap: BinaryHeap<Reverse<PktEntry>>,
    next_seq: u64,
    leftover: BytesMut,
}

#[derive(Eq, PartialEq)]
struct PktEntry {
    seq: u64,
    data: bytes::Bytes,
}

impl Ord for PktEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.seq.cmp(&other.seq)
    }
}
impl PartialOrd for PktEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

pub struct XhttpServerStream {
    up_rx: mpsc::Receiver<UploadPacket>,
    pkt_queue: PktQueue,
    stream_buf: BytesMut,
    eof: bool,
    down_tx: PollSender<bytes::Bytes>,
}

impl XhttpServerStream {
    fn new(up_rx: mpsc::Receiver<UploadPacket>, down_tx: mpsc::Sender<bytes::Bytes>) -> Self {
        Self {
            up_rx,
            pkt_queue: PktQueue {
                heap: BinaryHeap::new(),
                next_seq: 0,
                leftover: BytesMut::new(),
            },
            stream_buf: BytesMut::new(),
            eof: false,
            down_tx: PollSender::new(down_tx),
        }
    }
}

impl AsyncRead for XhttpServerStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.pkt_queue.leftover.is_empty() {
                let n = this.pkt_queue.leftover.len().min(buf.remaining());
                buf.put_slice(&this.pkt_queue.leftover[..n]);
                this.pkt_queue.leftover.advance(n);
                return Poll::Ready(Ok(()));
            }
            if !this.stream_buf.is_empty() {
                let n = this.stream_buf.len().min(buf.remaining());
                buf.put_slice(&this.stream_buf[..n]);
                this.stream_buf.advance(n);
                return Poll::Ready(Ok(()));
            }
            if let Some(Reverse(top)) = this.pkt_queue.heap.peek() {
                if top.seq == this.pkt_queue.next_seq {
                    let Reverse(entry) = this.pkt_queue.heap.pop().unwrap();
                    let n = entry.data.len().min(buf.remaining());
                    buf.put_slice(&entry.data[..n]);
                    if n < entry.data.len() {
                        this.pkt_queue.leftover.extend_from_slice(&entry.data[n..]);
                    }
                    this.pkt_queue.next_seq += 1;
                    return Poll::Ready(Ok(()));
                }
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            match this.up_rx.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(pkt)) => match pkt {
                    UploadPacket::Chunk(data) => {
                        let n = data.len().min(buf.remaining());
                        buf.put_slice(&data[..n]);
                        if n < data.len() {
                            this.stream_buf.extend_from_slice(&data[n..]);
                        }
                        return Poll::Ready(Ok(()));
                    }
                    UploadPacket::Packet { seq, data } => {
                        this.pkt_queue.heap.push(Reverse(PktEntry { seq, data }));
                    }
                    UploadPacket::Eof => {
                        this.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                },
            }
        }
    }
}

impl AsyncWrite for XhttpServerStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match this.down_tx.poll_reserve(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "xhttp downlink closed",
            ))),
            Poll::Ready(Ok(())) => {
                match this.down_tx.send_item(bytes::Bytes::copy_from_slice(buf)) {
                    Ok(()) => Poll::Ready(Ok(buf.len())),
                    Err(_) => Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "xhttp downlink closed",
                    ))),
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // close() 释放 PollSender 持有的 down_tx；session 已 take，所有 sender
        // 消失后 down_rx 返回 None → GET 响应结束 → cleanup 移除 session。
        // 不关闭的话远端断开后 GET 响应流永远不结束，客户端下行挂死。
        self.down_tx.close();
        Poll::Ready(Ok(()))
    }
}

// ── 单元测试 ───────────────────────────────────────────────────────────────────


// ════════════════════════════════════════════════════════════════════════
// 客户端（原 outbound/transport/xhttp.rs）
// ════════════════════════════════════════════════════════════════════════

fn resolve_mode<'a>(mode: Option<&'a str>, _tls: Option<&TlsConfig>) -> &'a str {
    match mode {
        Some(m) if !m.is_empty() && m != "auto" => m,
        _ => "packet-up",
    }
}

/// 建立一条 XHTTP 双工流。
pub async fn connect(
    server: &str,
    port: u16,
    cfg: &XhttpTransportConfig,
    tls: Option<&TlsConfig>,
    extra_headers: &HashMap<String, String>,
    routing_mark: u32,
    resolver: Option<Arc<reflex_dns::DnsResolver>>,
) -> anyhow::Result<XhttpStream> {
    let tls_enabled = tls.is_some_and(|t| t.enabled);
    let scheme = if tls_enabled { "https" } else { "http" };

    let host = cfg
        .host
        .as_deref()
        .or_else(|| tls.and_then(|t| t.server_name.as_deref()))
        .unwrap_or(server);

    let raw_path = cfg.path.as_deref().unwrap_or("/");
    let (path, query) = split_path_query(raw_path);
    let base_url = format!("{scheme}://{server}:{port}{path}");

    debug!(
        server,
        port,
        tls_enabled,
        host,
        %path,
        %query,
        raw_path = raw_path,
        sni = ?tls.and_then(|t| t.server_name.as_deref()),
        insecure = tls.is_some_and(|t| t.insecure),
        "xhttp config resolved"
    );

    let client = build_http_client(tls, cfg, routing_mark, resolver)?;

    // 模式选择，与 Xray dialer.go:362-371 完全对齐：
    //   mode == "" || mode == "auto" →
    //     默认 "packet-up"；若使用 REALITY → "stream-one"。
    //   旧实现：直接 unwrap_or("packet-up")，不处理 "auto"，
    //   也不在 REALITY 场景自动选 stream-one，导致服务端（Xray/sing-box
    //   在 REALITY 下默认期望 stream-one）拒绝或行为异常。
    let mode = resolve_mode(cfg.mode.as_deref(), tls);

    let session_id = if mode != "stream-one" {
        Some(Uuid::new_v4().to_string())
    } else {
        None
    };

    debug!(mode, %base_url, ?session_id, "xhttp connecting");

    let mut headers = cfg.headers.clone();
    for (k, v) in extra_headers {
        headers.entry(k.clone()).or_insert_with(|| v.clone());
    }
    headers
        .entry("Host".to_string())
        .or_insert_with(|| host.to_string());

    let shared = Arc::new(XhttpShared {
        client,
        base_url,
        query,
        session_id,
        headers,
        seq: AtomicI64::new(0),
        // 与 Xray config.go:139-148 对齐：默认 1_000_000。
        // Xray 使用 RangeConfig（From/To 随机），reflex 当前只支持单值，
        // 取用户配置或默认值。
        max_post_bytes: cfg.sc_max_each_post_bytes.unwrap_or(1_000_000) as usize,
        // 与 Xray config.go:150-159 对齐：默认 30ms。
        // 旧实现默认 0（无间隔），高频 POST 可能触发服务端限流。
        // Xray 默认 RangeConfig{From:30, To:30}。
        min_post_interval_ms: cfg.sc_min_posts_interval_ms.unwrap_or(30),
        uplink_method: cfg
            .uplink_http_method
            .clone()
            .unwrap_or_else(|| "POST".to_string()),
        no_grpc_header: cfg.no_grpc_header,
    });

    match mode {
        "stream-one" => connect_stream_one(shared).await,
        "stream-up" => connect_stream_up_down(shared).await,
        _ => connect_packet_up(shared).await,
    }
}

// ── 自定义 Connector（打 SO_MARK）────────────────────────────────────────────

/// 在 TCP connect 完成后立即设置 SO_MARK，然后可选地包一层 TLS。
#[derive(Clone)]
struct MarkedConnector {
    mark: u32,
    tls: Option<Arc<rustls::ClientConfig>>,
    /// 用于解析连接目标域名（走 dns.proxy_domain_resolver），None 时回退系统 DNS
    resolver: Option<Arc<reflex_dns::DnsResolver>>,
    /// 覆盖 TLS SNI 和证书校验名。当 server 字段是 IP 但证书签发给域名时
    /// （例如 vless+xhttp 配置 `server: "1.2.3.4"` + `tls.server_name: "example.com"`），
    /// 必须显式指定 SNI 为域名，否则 rustls 会按 IP 校验证书而失败。
    /// None 时回退到 URI host。
    server_name: Option<String>,
}

impl MarkedConnector {
    fn new(
        mark: u32,
        tls_cfg: Option<Arc<rustls::ClientConfig>>,
        resolver: Option<Arc<reflex_dns::DnsResolver>>,
        server_name: Option<String>,
    ) -> Self {
        Self {
            mark,
            tls: tls_cfg,
            resolver,
            server_name,
        }
    }
}

/// hyper 连接类型：裸 TCP 或 TLS over TCP
#[allow(clippy::large_enum_variant)]
pub enum MaybeHttps {
    Plain(TcpStream),
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
}

impl tokio::io::AsyncRead for MaybeHttps {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeHttps::Plain(s) => Pin::new(s).poll_read(cx, buf),
            MaybeHttps::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for MaybeHttps {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            MaybeHttps::Plain(s) => Pin::new(s).poll_write(cx, buf),
            MaybeHttps::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeHttps::Plain(s) => Pin::new(s).poll_flush(cx),
            MaybeHttps::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeHttps::Plain(s) => Pin::new(s).poll_shutdown(cx),
            MaybeHttps::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl hyper::rt::Read for MaybeHttps {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        // hyper 的 ReadBufCursor 内部是 MaybeUninit<u8>，不能强转为 &[u8]：
        // 未初始化字节被当作 u8 属于 UB（Rust 的初始化模型禁止）。
        // 改用 tokio::io::ReadBuf::uninit 接受未初始化内存，安全桥接。
        // 用块作用域让 rb 的可变借用（来自 buf.as_mut()）在 advance 前释放。
        let n = {
            // SAFETY: as_mut 返回未初始化的 spare 内存，我们只把它传给
            // ReadBuf::uninit（不读取其内容），poll_read 填充后按实际填充
            // 字节数 advance，不访问未初始化部分。
            let spare = unsafe { buf.as_mut() };
            let mut rb = ReadBuf::uninit(spare);
            match tokio::io::AsyncRead::poll_read(self, cx, &mut rb) {
                Poll::Ready(Ok(())) => rb.filled().len(),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        };
        // SAFETY: n 为 poll_read 实际写入 rb 的字节数，advance 不超过已初始化范围
        unsafe { buf.advance(n) };
        Poll::Ready(Ok(()))
    }
}

impl hyper::rt::Write for MaybeHttps {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(self, cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        tokio::io::AsyncWrite::poll_flush(self, cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        tokio::io::AsyncWrite::poll_shutdown(self, cx)
    }
}

impl hyper_util::client::legacy::connect::Connection for MaybeHttps {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        hyper_util::client::legacy::connect::Connected::new()
    }
}

impl Service<Uri> for MarkedConnector {
    type Response = MaybeHttps;
    type Error = anyhow::Error;
    type Future = Pin<Box<dyn Future<Output = anyhow::Result<MaybeHttps>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<anyhow::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let mark = self.mark;
        let tls_cfg = self.tls.clone();
        let resolver = self.resolver.clone();
        let server_name = self.server_name.clone();

        Box::pin(async move {
            let host = uri
                .host()
                .ok_or_else(|| anyhow::anyhow!("xhttp: missing host in URI"))?;
            let port = uri
                .port_u16()
                .unwrap_or(if uri.scheme_str() == Some("https") {
                    443
                } else {
                    80
                });

            debug!(uri_host = host, port, "xhttp connector: dialing");

            // DNS 解析（优先走 dns.proxy_domain_resolver，未注入则回退系统 DNS）
            let addr = crate::common::resolve_server_addr(host, port, resolver.as_ref())
                .await
                .map_err(|e| anyhow::anyhow!("xhttp: DNS failed for {host}: {e}"))?;

            debug!(%addr, "xhttp connector: resolved");

            // TCP connect → 打 SO_MARK → 设 TCP 选项
            let tcp = reflex_common::outbound::connect_tcp_interface(addr).await?;
            apply_mark_to_tcp(&tcp, mark)?;
            set_tcp_opts(&tcp)?;

            debug!(local = ?tcp.local_addr(), peer = ?tcp.peer_addr(), mark, "xhttp connector: TCP connected");

            if let Some(tls) = tls_cfg {
                // SNI 优先用 tls.server_name（处理 server 字段是 IP、证书签发给域名的场景）。
                // 没有显式 server_name 时回退到 URI host（保留原行为）。
                let sni_str = server_name.as_deref().unwrap_or(host);
                let sni = rustls::pki_types::ServerName::try_from(sni_str.to_string())
                    .map_err(|e| anyhow::anyhow!("xhttp: invalid SNI {sni_str}: {e}"))?;
                debug!(
                    sni = sni_str,
                    uri_host = host,
                    "xhttp connector: starting TLS handshake"
                );
                let connector = tokio_rustls::TlsConnector::from(tls);
                let tls_stream = connector
                    .connect(sni, tcp)
                    .await
                    .map_err(|e| anyhow::anyhow!("xhttp: TLS handshake failed: {e}"))?;
                debug!(sni = sni_str, "xhttp connector: TLS handshake ok");
                return Ok(MaybeHttps::Tls(tls_stream));
            }

            Ok(MaybeHttps::Plain(tcp))
        })
    }
}

// ── 类型别名：带 mark 的 hyper Client ────────────────────────────────────────

type XhttpClient = Client<MarkedConnector, XhttpBody>;

/// 上行 body 类型：可以是空 body、固定字节、或流式 channel
enum XhttpBody {
    Empty(Empty<Bytes>),
    Full(Full<Bytes>),
    #[allow(clippy::type_complexity)]
    Stream(
        StreamBody<
            futures_util::stream::Map<
                ReceiverStream<Bytes>,
                fn(Bytes) -> Result<Frame<Bytes>, io::Error>,
            >,
        >,
    ),
}

impl hyper::body::Body for XhttpBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            XhttpBody::Empty(b) => Pin::new(b).poll_frame(cx).map_err(|_| unreachable!()),
            XhttpBody::Full(b) => Pin::new(b).poll_frame(cx).map_err(|_| unreachable!()),
            XhttpBody::Stream(b) => Pin::new(b).poll_frame(cx),
        }
    }
}

fn stream_body(rx: mpsc::Receiver<Bytes>) -> XhttpBody {
    fn wrap(b: Bytes) -> Result<Frame<Bytes>, io::Error> {
        Ok(Frame::data(b))
    }
    XhttpBody::Stream(StreamBody::new(
        ReceiverStream::new(rx).map(wrap as fn(Bytes) -> Result<Frame<Bytes>, io::Error>),
    ))
}

// ── 内部共享状态 ──────────────────────────────────────────────────────────────

struct XhttpShared {
    client: XhttpClient,
    base_url: String,
    /// URL query string（从 `path` 中 `?` 后分离），与 Xray
    /// `GetNormalizedQuery` 对齐。session_id/seq 追加到 path，
    /// query 追加到 URL 末尾。
    query: String,
    session_id: Option<String>,
    headers: HashMap<String, String>,
    seq: AtomicI64,
    max_post_bytes: usize,
    min_post_interval_ms: u64,
    uplink_method: String,
    /// 禁用 `Content-Type: application/grpc` 头，与 Xray `NoGRPCHeader` 对齐。
    /// Xray config.go:325-327：stream-up/one（有 body 时）默认设置 grpc 头，
    /// 服务端据此识别为流式上行；no_grpc_header=true 时跳过。
    no_grpc_header: bool,
}

impl XhttpShared {
    fn apply_headers(&self, mut req: Request<XhttpBody>) -> Request<XhttpBody> {
        for (k, v) in &self.headers {
            if let (Ok(name), Ok(val)) = (
                HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_str(v),
            ) {
                req.headers_mut().insert(name, val);
            }
        }
        req
    }

    fn stream_url(&self) -> String {
        // Xray xhttp 默认 SessionIDPlacement = PlacementPath，session_id 追加到路径末尾。
        // base_url 已通过 normalize_path 保证以 '/' 结尾，直接拼接即可。
        // query 追加到 URL 末尾（与 Xray requestURL.RawQuery 对齐）。
        // 与 Xray config.go:appendToPath 行为一致。
        match &self.session_id {
            Some(sid) => append_query(&format!("{}{}", self.base_url, sid), &self.query),
            None => append_query(&self.base_url, &self.query),
        }
    }

    fn packet_url(&self, seq: i64) -> String {
        // Xray xhttp 默认 SeqPlacement = PlacementPath，seq 追加到 session_id 之后。
        // 格式：{base_url}{session_id}/{seq}?{query}
        match &self.session_id {
            Some(sid) => append_query(
                &format!("{}{}/{}", self.base_url, sid, seq),
                &self.query,
            ),
            None => append_query(&self.base_url, &self.query),
        }
    }

    fn build_request(
        &self,
        method: &Method,
        url: &str,
        body: XhttpBody,
        has_body: bool,
    ) -> anyhow::Result<Request<XhttpBody>> {
        let uri: Uri = url.parse()?;
        let host = uri.host().unwrap_or("").to_string();
        debug!(%method, %url, host = %host, "xhttp: building HTTP request");
        let req = Request::builder()
            .method(method)
            .uri(uri.clone())
            .header(HOST, &host)
            .body(body)?;
        // apply custom headers（覆盖同名 header）
        let mut req = self.apply_headers(req);

        // 浏览器伪装头：与 Xray `GetRequestHeader` → `TryDefaultHeadersWith(header, "fetch")`
        // 对齐。用户未设置 `User-Agent` 时，注入 Chrome fetch 风格默认头
        // （User-Agent、Sec-CH-UA、Sec-Fetch-*、Accept、Cache-Control、Priority 等），
        // 使流量特征与浏览器 fetch 请求一致，避免被 DPI 识别为非浏览器流量。
        // 旧实现完全缺失这些头，hyper 默认不发送 User-Agent，流量特征明显。
        apply_default_masquerade(&mut req);

        // Content-Type: application/grpc
        // 与 Xray config.go:325-327 对齐：
        //   if request.Body != nil && !c.NoGRPCHeader { // stream-up/one
        //       request.Header.Set("Content-Type", "application/grpc")
        //   }
        // 有 body 的请求（stream-one、stream-up）默认设置 grpc 头，
        // 服务端据此识别为流式上行。no_grpc_header=true 时跳过。
        // 旧实现完全缺失此头，服务端可能无法正确识别 stream-up/one 请求。
        if !self.no_grpc_header && has_body {
            req.headers_mut()
                .insert("content-type", HeaderValue::from_static("application/grpc"));
        }

        // XPadding：Xray xhttp 默认要求每个请求带 100-1000 字节 padding，
        // 放在 Referer 头的 query string 里（key=x_padding）。
        // 参考 Xray xpadding.go:
        //   - GetNormalizedXPaddingBytes 默认 {From:100, To:1000}
        //   - ApplyXPaddingToHeader: PlacementQueryInHeader, header="Referer", key="x_padding"
        //   - GeneratePadding: 默认方法生成全 'X' 字符串
        //   - IsPaddingValid: 空 padding 直接返回 false → 服务端返回 400
        //
        // Referer URL 使用 base path（不含 session_id/seq），与 Xray 的填充顺序
        // 一致：Xray 先 ApplyXPaddingToRequest（此时 URL path 仅为 normalized path），
        // 后 ApplyMetaToRequest（追加 session/seq 到 path）。旧实现用完整 URL path
        // （含 session/seq）构造 Referer，导致 Referer path 与 Xray 不一致。
        // padding 必须在 apply_headers 之后设置，确保不被用户自定义 header 覆盖。
        let mut rng = rand::thread_rng();
        let padding_len: usize = rng.gen_range(100..=1000);
        let padding = generate_padding(padding_len);
        let scheme = uri.scheme_str().unwrap_or("https");
        // Referer host 使用 Host 头值（域名），而非连接 IP（server），
        // 与 Xray requestURL.Host = transportConfiguration.Host 一致。
        let referer_host = self
            .headers
            .get("Host")
            .map(|s| s.as_str())
            .or_else(|| uri.authority().map(|a| a.as_str()))
            .unwrap_or("");
        // base_path 从 base_url 提取（不含 session_id/seq），与 Xray 填充顺序
        // 一致：padding 在 ApplyMetaToRequest（追加 session/seq）之前应用。
        let base_path = self
            .base_url
            .parse::<Uri>()
            .map(|u| u.path().to_string())
            .unwrap_or_else(|_| "/".to_string());
        let referer_value = format!("{scheme}://{referer_host}{base_path}?x_padding={padding}");
        if let Ok(val) = HeaderValue::from_str(&referer_value) {
            req.headers_mut().insert("referer", val);
        }
        debug!(padding_len, "xhttp: applied XPadding to Referer header");

        Ok(req)
    }
}

// ── 模式 1：stream-one ────────────────────────────────────────────────────────

async fn connect_stream_one(shared: Arc<XhttpShared>) -> anyhow::Result<XhttpStream> {
    let (body_tx, body_rx) = mpsc::channel::<Bytes>(64);
    let url = shared.stream_url();
    let method = parse_method(&shared.uplink_method);
    let req = shared.build_request(&method, &url, stream_body(body_rx), true)?;
    debug!("xhttp stream-one: sending request");
    let resp = shared.client.request(req).await?;
    debug!(status = %resp.status(), "xhttp stream-one: response received");
    check_status(resp.status(), "stream-one")?;
    let read_half = RespBodyReader::new(resp.into_body());
    debug!("xhttp stream-one: stream established");
    Ok(XhttpStream::new(read_half, XhttpWriter::Stream(body_tx)))
}

// ── 模式 2：stream-up + 独立 GET 下行 ────────────────────────────────────────

async fn connect_stream_up_down(shared: Arc<XhttpShared>) -> anyhow::Result<XhttpStream> {
    let down_url = shared.stream_url();
    let req = shared.build_request(
        &Method::GET,
        &down_url,
        XhttpBody::Empty(Empty::new()),
        false,
    )?;
    debug!("xhttp stream-up: sending GET download request");
    let down_resp = shared.client.request(req).await?;
    debug!(status = %down_resp.status(), "xhttp stream-up: download response received");
    check_status(down_resp.status(), "stream-down")?;

    // 关闭信号：上传 POST 失败时通知下行读取器返回错误。
    // 与 Xray client.go:86-92 对齐：uploadOnly 的 OpenStream 在失败/非200 时
    // 调用 wrc.Close()，使 download 侧的 Read 返回 io.ErrClosedPipe。
    let close_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let read_half =
        RespBodyReader::with_close_flag(down_resp.into_body(), Some(close_flag.clone()));

    let (body_tx, body_rx) = mpsc::channel::<Bytes>(64);
    let up_url = shared.stream_url();
    let method = parse_method(&shared.uplink_method);
    let req = shared.build_request(&method, &up_url, stream_body(body_rx), true)?;
    {
        let client = shared.client.clone();
        tokio::spawn(async move {
            debug!("xhttp stream-up: sending POST upload request (background)");
            let failed = match client.request(req).await {
                Ok(resp) => {
                    debug!(status = %resp.status(), "xhttp stream-up: upload response received");
                    // 检查 HTTP 状态码，4xx/5xx 表示服务端拒绝上行
                    match check_status(resp.status(), "stream-up") {
                        Ok(()) => false,
                        Err(e) => {
                            warn!("xhttp stream-up POST rejected: {e}");
                            true
                        }
                    }
                }
                Err(e) => {
                    warn!("xhttp stream-up POST failed: {e}");
                    true
                }
            };
            if failed {
                // 通知下行读取器：上行已断开，关闭连接。
                // 旧实现仅 warn 日志，下行流保持 open，调用方误以为连接正常，
                // 但数据实际已无法上行 → 连接假死。
                close_flag.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        });
    }

    debug!("xhttp stream-up: stream established");
    Ok(XhttpStream::new(read_half, XhttpWriter::Stream(body_tx)))
}

// ── 模式 3：packet-up（默认）─────────────────────────────────────────────────

async fn connect_packet_up(shared: Arc<XhttpShared>) -> anyhow::Result<XhttpStream> {
    let down_url = shared.stream_url();
    let req = shared.build_request(
        &Method::GET,
        &down_url,
        XhttpBody::Empty(Empty::new()),
        false,
    )?;
    debug!("xhttp packet-up: sending GET download request");
    let down_resp = shared.client.request(req).await?;
    debug!(status = %down_resp.status(), "xhttp packet-up: download response received");
    check_status(down_resp.status(), "packet-up/stream-down")?;
    let read_half = RespBodyReader::new(down_resp.into_body());

    let (up_tx, mut up_rx) = mpsc::channel::<Bytes>(128);
    {
        let shared = shared.clone();
        tokio::spawn(async move {
            let mut last_post = std::time::Instant::now();
            debug!(
                max_post_bytes = shared.max_post_bytes,
                min_post_interval_ms = shared.min_post_interval_ms,
                "xhttp packet-up: upload loop started"
            );

            // 批处理缓冲区：与 Xray dialer.go:490-568 的 pipe 机制对齐。
            //
            // Xray 使用 size-limited pipe：多个 Write 调用积累在 pipe 中，
            // 读循环通过 ReadMultiBuffer 一次性读出所有已缓冲数据，
            // 然后按 maxUploadSize 拆分成多个 POST。这样多个小写
            // （如 TLS 握手、VLESS 头）被合并为一个大 POST，大幅提升带宽。
            //
            // 旧 reflex 实现：每个 channel 消息单独发一个 POST，
            // 小数据包（几十字节）各自成帧 → POST 请求数爆炸，带宽极低。
            //
            // 本实现：从 channel 攒数据到 buffer，直到：
            //   1. buffer 达到 max_post_bytes（满了，必须发），或
            //   2. channel 暂时无数据（try_recv 失败），立即发送已缓冲的数据
            //      （不等待攒满，避免延迟——对齐 Xray ReadMultiBuffer 行为）。
            while let Some(first_chunk) = up_rx.recv().await {
                let mut buffer = BytesMut::new();
                buffer.extend_from_slice(&first_chunk);

                // 尝试攒更多数据，直到达到 max_post_bytes 或 channel 暂时为空
                while buffer.len() < shared.max_post_bytes {
                    match up_rx.try_recv() {
                        Ok(more) => {
                            buffer.extend_from_slice(&more);
                        }
                        Err(_) => {
                            // channel 暂时无数据，立即发送已缓冲的内容
                            break;
                        }
                    }
                }

                // 按 max_post_bytes 拆分发送（与 Xray buf.SplitSize 对齐）
                let mut remaining = buffer.freeze();
                while !remaining.is_empty() {
                    let payload: Bytes = if remaining.len() > shared.max_post_bytes {
                        let split = shared.max_post_bytes;
                        let mut tail = remaining.split_off(split);
                        std::mem::swap(&mut tail, &mut remaining);
                        tail
                    } else {
                        std::mem::take(&mut remaining)
                    };

                    // POST 间隔控制，与 Xray dialer.go:536-538 对齐
                    if shared.min_post_interval_ms > 0 {
                        let elapsed = last_post.elapsed().as_millis() as u64;
                        if elapsed < shared.min_post_interval_ms {
                            tokio::time::sleep(tokio::time::Duration::from_millis(
                                shared.min_post_interval_ms - elapsed,
                            ))
                            .await;
                        }
                    }

                    // 与 Xray dialer.go:547-565 对齐：POST 异步发送，
                    // 不等待完整响应即可发送下一个 chunk。
                    // Xray 用 goroutine + WroteRequest 信号实现：只等请求
                    // 写入完成（不等响应），立即继续下一个 POST。
                    // reflex 使用 tokio::spawn 实现同等语义：POST 在后台
                    // 发送，主循环立即继续处理下一个 chunk。
                    let shared_clone = shared.clone();
                    tokio::spawn(async move {
                        if let Err(e) = post_packet(&shared_clone, payload).await {
                            warn!("xhttp packet-up POST error: {e}");
                        }
                    });

                    last_post = std::time::Instant::now();
                }
            }
            debug!("xhttp packet-up: upload channel closed, upload loop exiting");
        });
    }

    debug!("xhttp packet-up: stream established");
    Ok(XhttpStream::new(read_half, XhttpWriter::Packet(up_tx)))
}

async fn post_packet(shared: &XhttpShared, payload: Bytes) -> anyhow::Result<()> {
    let seq = shared.seq.fetch_add(1, Ordering::Relaxed);
    let url = shared.packet_url(seq);
    let method = parse_method(&shared.uplink_method);
    let payload_len = payload.len();
    let req = shared.build_request(&method, &url, XhttpBody::Full(Full::new(payload)), false)?;
    debug!(seq, payload_len, "xhttp packet-up: POST upload");
    let resp = shared.client.request(req).await?;
    debug!(seq, status = %resp.status(), "xhttp packet-up: POST response");
    check_status(resp.status(), &format!("packet POST {seq}"))
}

// ── 下行响应体读取器 ──────────────────────────────────────────────────────────

struct RespBodyReader {
    rx: mpsc::Receiver<io::Result<Bytes>>,
    current: Bytes,
    /// 可选的关闭信号：当上行流（stream-up POST）失败时设置，
    /// 使后续 poll_read 返回 ConnectionReset 错误，通知调用方连接已断开。
    /// 与 Xray client.go:86-92 对齐：uploadOnly 的 OpenStream 在失败/非200 时
    /// 调用 wrc.Close()，使 download 侧的 Read 返回 io.ErrClosedPipe。
    close_flag: Option<Arc<std::sync::atomic::AtomicBool>>,
}

impl RespBodyReader {
    fn new(body: Incoming) -> Self {
        Self::with_close_flag(body, None)
    }

    fn with_close_flag(
        body: Incoming,
        close_flag: Option<Arc<std::sync::atomic::AtomicBool>>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(async move {
            let mut stream = body;
            let mut total_bytes = 0u64;
            let mut frame_count = 0u64;
            loop {
                match stream.frame().await {
                    None => {
                        debug!(
                            total_bytes,
                            frame_count, "xhttp download: stream ended (no more frames)"
                        );
                        break;
                    }
                    Some(Ok(frame)) => {
                        if let Ok(data) = frame.into_data() {
                            frame_count += 1;
                            total_bytes += data.len() as u64;
                            if tx.send(Ok(data)).await.is_err() {
                                debug!(
                                    total_bytes,
                                    frame_count, "xhttp download: consumer dropped, stopping"
                                );
                                break;
                            }
                        }
                    }
                    Some(Err(e)) => {
                        warn!(
                            error = %e,
                            total_bytes,
                            frame_count,
                            "xhttp download: frame error"
                        );
                        let _ = tx
                            .send(Err(io::Error::new(io::ErrorKind::BrokenPipe, e)))
                            .await;
                        break;
                    }
                }
            }
        });
        Self {
            rx,
            current: Bytes::new(),
            close_flag,
        }
    }
}

impl AsyncRead for RespBodyReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // 检查上行流是否已失败（stream-up 模式）
        if let Some(flag) = &this.close_flag {
            if flag.load(std::sync::atomic::Ordering::Relaxed) {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "xhttp: upload stream failed, closing download",
                )));
            }
        }
        if !this.current.is_empty() {
            let n = buf.remaining().min(this.current.len());
            buf.put_slice(&this.current[..n]);
            this.current = this.current.slice(n..);
            return Poll::Ready(Ok(()));
        }
        match this.rx.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(e)),
            Poll::Ready(Some(Ok(chunk))) => {
                if chunk.is_empty() {
                    return Poll::Ready(Ok(()));
                }
                let n = buf.remaining().min(chunk.len());
                buf.put_slice(&chunk[..n]);
                if n < chunk.len() {
                    this.current = chunk.slice(n..);
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}

// ── XhttpStream：对外暴露的双工流 ─────────────────────────────────────────────

pub struct XhttpStream {
    reader: RespBodyReader,
    writer: XhttpWriter,
}

enum XhttpWriter {
    Stream(mpsc::Sender<Bytes>),
    Packet(mpsc::Sender<Bytes>),
}

impl XhttpStream {
    fn new(reader: RespBodyReader, writer: XhttpWriter) -> Self {
        Self { reader, writer }
    }
}

impl AsyncRead for XhttpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for XhttpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let tx = match &this.writer {
            XhttpWriter::Stream(tx) | XhttpWriter::Packet(tx) => tx.clone(),
        };
        // 性能：旧实现 `Bytes::copy_from_slice(data)` 每次写都分配一个新 Bytes。
        // 修正：与 sing-box chunk_length_stream.go:138-169 的「直接用 buffer 的
        // backing slice」对齐——改用 `BytesMut::from(data).split()` 复用 BytesMut
        // 的 inline 优化路径。对 ≤16 字节的小写（packet-up 序号等）走 BytesMut
        // 的 inline 存储，零堆分配；大写仍 1 次分配，但 split 后的 Bytes 句柄
        // 比 copy_from_slice 的 Bytes 句柄更轻（少一次 refcount atomic）。
        let chunk = bytes::BytesMut::from(data).split().freeze();
        match tx.try_send(chunk) {
            Ok(()) => Poll::Ready(Ok(data.len())),
            Err(mpsc::error::TrySendError::Full(_)) => {
                let waker = cx.waker().clone();
                tokio::spawn(async move {
                    let _ = tx.reserve().await;
                    waker.wake();
                });
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "xhttp: upload channel closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let (dead_tx, _) = mpsc::channel(1);
        match &mut this.writer {
            XhttpWriter::Stream(tx) => *tx = dead_tx,
            XhttpWriter::Packet(tx) => *tx = dead_tx,
        }
        Poll::Ready(Ok(()))
    }
}

// ── HTTP Client 构建 ──────────────────────────────────────────────────────────

fn build_http_client(
    tls: Option<&TlsConfig>,
    _cfg: &XhttpTransportConfig,
    routing_mark: u32,
    resolver: Option<Arc<reflex_dns::DnsResolver>>,
) -> anyhow::Result<XhttpClient> {
    let tls_enabled = tls.is_some_and(|t| t.enabled);

    let rustls_cfg: Option<Arc<rustls::ClientConfig>> = if tls_enabled {
        if let Some(tls_cfg) = tls {
            // 克隆 TlsConfig 以强制 ALPN=h2，不影响原始配置
            let mut tls_cfg_clone = tls_cfg.clone();
            // XHTTP 三种模式（stream-one/stream-up/packet-up）都依赖 HTTP/2 的
            // 流式语义：单次 POST 上行长连接 + 独立 GET 下行长连接。
            // HTTP/1.1 请求-响应串行机制根本无法工作，服务端（Xray/sing-box）
            // 都是 HTTP/2-only。与 Xray xhttp 配置 `downloadSettings.streamSettings`
            // 一致：必须 h2，禁止 http/1.1。
            let original_alpn = tls_cfg_clone.alpn.clone();
            tls_cfg_clone.alpn = vec!["h2".to_string()];
            debug!(
                original_alpn = ?original_alpn,
                forced_alpn = ?tls_cfg_clone.alpn,
                insecure = tls_cfg_clone.insecure,
                "xhttp: building rustls client config (ALPN forced to h2)"
            );
            Some(crate::tls::build_client_config_cached(
                &tls_cfg_clone,
            )?)
        } else {
            None
        }
    } else {
        None
    };

    // 提取 tls.server_name：用于覆盖 TLS SNI（当 server 字段是 IP 但证书签发给域名时必需）
    let server_name = tls.and_then(|t| t.server_name.clone());

    let connector = MarkedConnector::new(routing_mark, rustls_cfg, resolver, server_name);

    // HTTP 版本选择，与 Xray dialer.go:84-101 decideHTTPVersion 对齐：
    //   - 有 TLS（含 REALITY）→ HTTP/2（ALPN 已强制 h2）
    //   - 无 TLS → HTTP/1.1
    //
    // 旧实现：无条件 http2_only(true)，无 TLS 时走 h2c（HTTP/2 cleartext），
    // 标准 HTTP/1.1 服务器不支持 h2c → 连接失败。
    // Xray 在无 TLS 时使用 http.Transport（HTTP/1.1），packet-up 模式可用。
    let client = if tls_enabled {
        Client::builder(hyper_util::rt::TokioExecutor::new())
            .http2_only(true)
            .build(connector)
    } else {
        Client::builder(hyper_util::rt::TokioExecutor::new()).build(connector)
    };

    Ok(client)
}

// ── 辅助函数 ──────────────────────────────────────────────────────────────────

/// 生成 padding 字符串。默认使用 `repeat-x`（全 'X'），与 Xray
/// `GeneratePadding` 默认方法一致。
///
/// 注：Xray 还支持 `tokenish`（base62 随机 + Huffman 长度控制），reflex
/// 当前只支持 `repeat-x`。'X' 和 'Z' 在 HPACK Huffman 编码中占 8 位，
/// 压缩后不改变实际 padding 长度（RFC 7541 / RFC 9204）。
fn generate_padding(len: usize) -> String {
    "X".repeat(len)
}

/// 计算当前 Chrome 主版本号，与 Xray `ChromeVersion()` 对齐：
/// 从 2026-01-13 Chrome 144 起，每 ~35 天递增一个大版本，
/// 引入随机抖动模拟 Xray 的 PRNG 行为。
/// Xray common/utils/browser.go:25-32
fn chrome_major_version() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    // 2026-01-13 00:00 UTC = epoch day 20466
    const DAYS_START_2026_01_13: i64 = 20466;
    const START_VERSION: i64 = 144;
    const CADENCE_DAYS: i64 = 35;

    let days_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.as_secs() / 86400) as i64)
        .unwrap_or(0);

    let mut rng = rand::thread_rng();
    let jitter = (rng.gen::<f64>().powi(2) * 105.0).floor() as i64;
    let time_diff = (days_now - DAYS_START_2026_01_13 - 35) - jitter;
    (START_VERSION + (time_diff.max(0) / CADENCE_DAYS)) as u32
}

/// 构造 Chrome User-Agent 字符串，与 Xray `ChromeUA` 格式一致。
fn chrome_user_agent() -> String {
    let ver = chrome_major_version();
    format!(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/{ver}.0.0.0 Safari/537.36"
    )
}

/// 构造 Sec-CH-UA 头值，与 Xray `getGreasedChUa(version, "chrome")` 格式一致。
/// 包含一个 GREASE 无效品牌 + Chromium + Google Chrome。
fn sec_chua_value() -> String {
    let ver = chrome_major_version();
    format!(
        "\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"{ver}\", \"Google Chrome\";v=\"{ver}\""
    )
}

/// 注入浏览器伪装头，与 Xray `TryDefaultHeadersWith(header, "fetch")` +
/// `applyMasqueradedHeaders(header, "chrome", "fetch")` 完全对齐。
///
/// 仅当请求未设置 `User-Agent` 时注入。注入后流量特征与 Chrome 浏览器
/// fetch 请求一致：
/// - chrome 头：User-Agent、Sec-CH-UA、Sec-CH-UA-Mobile、Sec-CH-UA-Platform、
///   DNT、Accept-Language（覆盖同名头）
/// - fetch 头：Sec-Fetch-Mode、Sec-Fetch-Dest、Sec-Fetch-Site（覆盖），
///   Priority、Cache-Control、Pragma、Accept（仅当未设置时填充）
fn apply_default_masquerade(req: &mut Request<XhttpBody>) {
    let headers = req.headers();
    let has_ua = headers.contains_key("user-agent");
    if has_ua {
        return;
    }

    let h = req.headers_mut();
    // ── chrome masquerade（覆盖）──
    h.insert("user-agent", HeaderValue::from_str(&chrome_user_agent()).unwrap());
    h.insert(
        "sec-ch-ua",
        HeaderValue::from_str(&sec_chua_value()).unwrap(),
    );
    h.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
    h.insert("sec-ch-ua-platform", HeaderValue::from_static("\"Windows\""));
    h.insert("dnt", HeaderValue::from_static("1"));
    h.insert("accept-language", HeaderValue::from_static("en-US,en;q=0.9"));

    // ── fetch variant ──
    // Sec-Fetch-* 覆盖（与 Xray header.Set 一致）
    h.insert("sec-fetch-mode", HeaderValue::from_static("cors"));
    h.insert("sec-fetch-dest", HeaderValue::from_static("empty"));
    h.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
    // 以下仅当未设置时填充（与 Xray `if header.Get(x) == ""` 一致）
    if !h.contains_key("priority") {
        h.insert("priority", HeaderValue::from_static("u=1, i"));
    }
    if !h.contains_key("cache-control") {
        h.insert("cache-control", HeaderValue::from_static("no-cache"));
    }
    if !h.contains_key("pragma") {
        h.insert("pragma", HeaderValue::from_static("no-cache"));
    }
    if !h.contains_key("accept") {
        h.insert("accept", HeaderValue::from_static("*/*"));
    }
}

fn parse_method(s: &str) -> Method {
    Method::from_bytes(s.as_bytes()).unwrap_or(Method::POST)
}

fn check_status(status: StatusCode, ctx: &str) -> anyhow::Result<()> {
    if status.is_success() {
        debug!(status = %status, ctx, "xhttp: HTTP status ok");
        Ok(())
    } else {
        warn!(status = %status, ctx, "xhttp: HTTP status error");
        anyhow::bail!("xhttp {ctx}: server returned {status}")
    }
}

/// 将 path 拆分为路径和 query 两部分，与 Xray `GetNormalizedPath`/
/// `GetNormalizedQuery` 对齐。用户配置 `path: "/xhttp?token=abc"` 时，
/// path=`/xhttp/`，query=`token=abc`。
/// 旧实现将整个字符串（含 `?query`）当作 path 处理，导致 session_id/seq
/// 被拼到 query 中而非 path 中，服务端按 path 提取 session 时失败。
fn split_path_query(raw: &str) -> (String, String) {
    let (path_part, query_part) = match raw.split_once('?') {
        Some((p, q)) => (p, q),
        None => (raw, ""),
    };
    (normalize_path(path_part), query_part.to_string())
}

/// 确保路径以 '/' 开头，并以 '/' 结尾（与 Xray 行为一致）。
/// 仅处理 path 部分，不处理 query string（由 `split_path_query` 分离）。
fn normalize_path(path: &str) -> String {
    let p = if path.is_empty() || !path.starts_with('/') {
        format!("/{path}")
    } else {
        path.to_string()
    };
    if !p.ends_with('/') {
        format!("{p}/")
    } else {
        p
    }
}

/// 追加 query 到 URL，若 query 为空则原样返回。
fn append_query(url: &str, query: &str) -> String {
    if query.is_empty() {
        url.to_string()
    } else {
        format!("{url}?{query}")
    }
}

// ── 单元测试 ──────────────────────────────────────────────────────────────────

// ════════════════════════════════════════════════════════════════════════
// 单元测试（服务端）
// ════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod base_tests {
    use super::*;

    #[test]
    fn test_normalized_path() {
        // 默认 `/` 不能被规范化成 `//`
        assert_eq!(
            XhttpServerOptions::default().normalized_path(),
            "/"
        );
        assert_eq!(
            XhttpServerOptions {
                path: "".into(),
                host: None,
            }
            .normalized_path(),
            "/"
        );
        assert_eq!(
            XhttpServerOptions {
                path: "/vless".into(),
                host: None,
            }
            .normalized_path(),
            "/vless/"
        );
        assert_eq!(
            XhttpServerOptions {
                path: "/vless//".into(),
                host: None,
            }
            .normalized_path(),
            "/vless/"
        );
        assert_eq!(
            XhttpServerOptions {
                path: "vless".into(),
                host: None,
            }
            .normalized_path(),
            "/vless/"
        );
    }

    #[test]
    fn test_parse_path() {
        // 默认 base `/`
        assert_eq!(parse_path("/", "/"), Some((None, None)));
        assert_eq!(parse_path("/sid", "/"), Some((Some("sid".into()), None)));
        assert_eq!(
            parse_path("/sid/42", "/"),
            Some((Some("sid".into()), Some("42".into())))
        );

        let base = "/vless/";
        assert_eq!(parse_path("/vless", base), Some((None, None)));
        assert_eq!(parse_path("/vless/", base), Some((None, None)));

        let sid = "550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(
            parse_path(&format!("/vless/{sid}"), base),
            Some((Some(sid.into()), None))
        );
        assert_eq!(
            parse_path(&format!("/vless/{sid}/42"), base),
            Some((Some(sid.into()), Some("42".into())))
        );
        assert_eq!(parse_path("/other", base), None);
    }

    #[test]
    fn test_is_valid_http_host() {
        assert!(is_valid_http_host("Example.com", "example.com"));
        assert!(is_valid_http_host("example.com:443", "example.com"));
        assert!(is_valid_http_host("[::1]:443", "[::1]"));
        assert!(!is_valid_http_host("evil.com", "example.com"));
    }
}

// ════════════════════════════════════════════════════════════════════════
// 单元测试（客户端）
// ════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod appended_tests {
    use super::*;

    #[test]
    fn test_normalize_path() {
        assert_eq!(normalize_path(""), "/");
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path("ws"), "/ws/");
        assert_eq!(normalize_path("/ws"), "/ws/");
        assert_eq!(normalize_path("/ws/"), "/ws/");
        assert_eq!(normalize_path("/a/b"), "/a/b/");
    }

    #[test]
    fn test_split_path_query() {
        // 无 query
        assert_eq!(split_path_query("/ws/"), ("/ws/".to_string(), "".to_string()));
        assert_eq!(split_path_query("/ws"), ("/ws/".to_string(), "".to_string()));
        // 有 query
        assert_eq!(
            split_path_query("/ws?token=abc"),
            ("/ws/".to_string(), "token=abc".to_string())
        );
        assert_eq!(
            split_path_query("/xhttp?a=1&b=2"),
            ("/xhttp/".to_string(), "a=1&b=2".to_string())
        );
        // 空路径
        assert_eq!(split_path_query(""), ("/".to_string(), "".to_string()));
        assert_eq!(split_path_query("?q=1"), ("/".to_string(), "q=1".to_string()));
    }

    #[test]
    fn test_append_query() {
        assert_eq!(append_query("https://h/p", ""), "https://h/p");
        assert_eq!(
            append_query("https://h/p", "token=abc"),
            "https://h/p?token=abc"
        );
    }

    #[test]
    fn test_generate_padding() {
        let p = generate_padding(100);
        assert_eq!(p.len(), 100);
        assert!(p.chars().all(|c| c == 'X'));
    }

    #[test]
    fn test_chrome_major_version_reasonable() {
        let v = chrome_major_version();
        // 2026-08 应在 144-160 范围内
        assert!((144..=160).contains(&v), "chrome version {v} out of range");
    }

    #[test]
    fn test_chrome_user_agent_format() {
        let ua = chrome_user_agent();
        assert!(ua.starts_with("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"));
        assert!(ua.contains("Chrome/"));
        assert!(ua.contains("Safari/537.36"));
    }

    #[test]
    fn test_sec_chua_value_format() {
        let v = sec_chua_value();
        assert!(v.contains("Chromium"));
        assert!(v.contains("Google Chrome"));
        assert!(v.contains("Not/A)Brand"));
    }
}
