//! 出站共享基建：双向转发（relay）、实时流量计数（CountedStream）、
//! 服务端地址解析，以及代理组（group：selector/urltest）与 smux 多路复用。
//! 各协议 `outbound.rs` 与 `transport/` 客户端共用。

pub mod group;
pub mod smux;

use std::{net::SocketAddr, sync::Arc};

use tokio::io::{AsyncRead, AsyncWrite};

use reflex_common::target::Target;
use reflex_dns::DnsResolver;


// ── 双向转发 ──────────────────────────────────────────────────────────────────

// 在两个异步读写流之间双向透明转发，支持 TCP half-close。
//
// 参照 sing-box `connectionCopy`：某方向读到 EOF 后调用对端的 `shutdown()`
// 发送 TCP FIN，让对端能干净地感知到写端关闭，而不是悬挂等待超时。
//
// 使用 64 KiB buffer（sing-box 批量 size），相比默认 8 KiB 对大流量吞吐
// 提升明显（减少系统调用次数）。
//
// 返回 `(a→b 字节数, b→a 字节数)`。

// ── CountedStream：包装任意 AsyncRead+AsyncWrite，实时更新计数器 ───────────────

/// 透明包装一个双向流，在每次 read（下载）和 write（上传）时
/// 实时更新 `live_up` / `live_down` 原子计数器。
/// 用于在不修改各出站实现的情况下，为所有代理出站提供实时流量统计。
pub struct CountedStream<S> {
    inner: S,
    live_up: std::sync::Arc<portable_atomic::AtomicI64>,
    live_down: std::sync::Arc<portable_atomic::AtomicI64>,
}

impl<S> CountedStream<S> {
    pub fn new(
        inner: S,
        live_up: std::sync::Arc<portable_atomic::AtomicI64>,
        live_down: std::sync::Arc<portable_atomic::AtomicI64>,
    ) -> Self {
        Self {
            inner,
            live_up,
            live_down,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountedStream<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::sync::atomic::Ordering;
        let before = buf.filled().len();
        let result = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        let after = buf.filled().len();
        if after > before {
            self.live_down
                .fetch_add((after - before) as i64, Ordering::Relaxed);
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountedStream<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::sync::atomic::Ordering;
        let result = std::pin::Pin::new(&mut self.inner).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(n)) = &result {
            self.live_up.fetch_add(*n as i64, Ordering::Relaxed);
        }
        result
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// 与 `relay` 相同，但每次转发时实时更新 `live_up` / `live_down` 原子计数器。
/// 供连接追踪器实时上报上传/下载字节数使用。
pub async fn relay_tracked<A, B>(
    a: A,
    b: B,
    live_up: std::sync::Arc<portable_atomic::AtomicI64>,
    live_down: std::sync::Arc<portable_atomic::AtomicI64>,
) -> (u64, u64)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);

    const BUF_SIZE: usize = 65536;

    let (r1, r2) = tokio::join!(
        copy_half_tracked(&mut ar, &mut bw, BUF_SIZE, live_up),
        copy_half_tracked(&mut br, &mut aw, BUF_SIZE, live_down),
    );
    (r1, r2)
}

async fn copy_half_tracked<R, W>(
    reader: &mut R,
    writer: &mut W,
    buf_size: usize,
    counter: std::sync::Arc<portable_atomic::AtomicI64>,
) -> u64
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use std::sync::atomic::Ordering;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; buf_size];
    let mut total = 0u64;
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if writer.write_all(&buf[..n]).await.is_err() {
            break;
        }
        // 与 copy_half 同步：WS 路径必须显式 flush 才会把数据真正写入底层 TCP。
        if writer.flush().await.is_err() {
            break;
        }
        total += n as u64;
        counter.fetch_add(n as i64, Ordering::Relaxed);
    }
    let _ = writer.shutdown().await;
    total
}

pub async fn relay<A, B>(a: A, b: B) -> (u64, u64)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);

    const BUF_SIZE: usize = 65536;

    let (r1, r2) = tokio::join!(
        copy_half(&mut ar, &mut bw, BUF_SIZE),
        copy_half(&mut br, &mut aw, BUF_SIZE),
    );
    (r1, r2)
}

/// 单方向 copy：读到 EOF 后向写端发 shutdown（TCP half-close FIN）。
async fn copy_half<R, W>(reader: &mut R, writer: &mut W, buf_size: usize) -> u64
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; buf_size];
    let mut total = 0u64;
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if writer.write_all(&buf[..n]).await.is_err() {
            break;
        }
        // 必须显式 flush：
        // 对 WebSocket（tokio-tungstenite）而言，poll_write 仅把 Binary 帧放入
        // tungstenite 内部 out_buffer，必须调用 poll_flush 才会真正写入底层 TCP。
        // 不加 flush 会导致 VLESS/Trojan + WS 的请求头与载荷滞留在缓冲区，
        // 服务端永远收不到请求，连接表现为卡死。
        // 对 TCP+TLS 路径 flush 几乎无开销（rustls 在 poll_write 时已写入 TCP）。
        if writer.flush().await.is_err() {
            break;
        }
        total += n as u64;
    }
    // 发送 FIN，通知对端写完了；忽略错误（连接可能已被对端关闭）
    let _ = writer.shutdown().await;
    total
}

// ── 目标地址解析 ──────────────────────────────────────────────────────────────

/// 解析「代理出站节点自身的服务器地址」（即各协议 outbound 配置里的 `server` 字段）。
///
/// - 若 `server` 已是 IP，直接返回，不查询 DNS。
/// - 若提供了 `resolver`，使用 `DnsResolver::resolve_proxy_domain`
///   （即 `dns.proxy_domain_resolver` 指定的上游，未配置则回退 dns.final 默认上游）。
/// - 若未注入 `resolver`（如未启用内置 DNS 模块），回退到系统 DNS，行为与之前一致。
pub async fn resolve_server_addr(
    server: &str,
    port: u16,
    resolver: Option<&Arc<DnsResolver>>,
) -> anyhow::Result<SocketAddr> {
    resolve_server_addr_for("", server, port, resolver).await
}

/// `resolve_server_addr` 的防环版本：`self_tag` 为本出站的 tag。
///
/// 必须用本函数替代旧版的原因（TUN auto_route 场景实测踩坑）：
/// 解析代理服务器域名时若 DNS 上游 detour 指向本出站自身，会形成
/// 「建连 → 解析 → 再建连」的死锁（连接缓存互斥锁被外层持有，嵌套调用
/// 永久阻塞），日志表现为 DNS 全部 `deadline has elapsed` 且没有任何
/// 代理连接错误。此版本：
///   1. 过滤掉 detour 指向 `self_tag` 自身的 DNS 上游（对齐 sing-box
///      对 domain_resolver 的 loop 约束）；
///   2. 整个解析过程加 5s 超时——即使上游卡死（如系统 DNS 被 TUN 劫持
///      后黑洞），也会快速报错而不是无限挂起。
pub async fn resolve_server_addr_for(
    self_tag: &str,
    server: &str,
    port: u16,
    resolver: Option<&Arc<DnsResolver>>,
) -> anyhow::Result<SocketAddr> {
    if let Ok(ip) = server.parse::<std::net::IpAddr>() {
        tracing::debug!(outbound = %self_tag, server = %server, %ip, "resolve_server_addr_for: literal IP, no DNS");
        return Ok(SocketAddr::new(ip, port));
    }
    tracing::debug!(outbound = %self_tag, server = %server, resolver_set = resolver.is_some(),
        "resolve_server_addr_for: domain, resolving");
    if let Some(r) = resolver {
        const BOOTSTRAP_DNS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
        let ip = tokio::time::timeout(
            BOOTSTRAP_DNS_TIMEOUT,
            r.resolve_proxy_domain_for_outbound(server, self_tag),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "bootstrap DNS timeout ({BOOTSTRAP_DNS_TIMEOUT:?}) resolving proxy \
                 server '{server}' (outbound '{self_tag}'); the DNS upstream is likely \
                 unreachable or looped through this outbound itself"
            )
        })??;
        Ok(SocketAddr::new(ip, port))
    } else {
        tracing::warn!(outbound = %self_tag, server = %server,
            "resolve_server_addr_for: no resolver, falling back to system getaddrinfo (with 5s timeout)");
        const SYS_LOOKUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
        tokio::time::timeout(
            SYS_LOOKUP_TIMEOUT,
            tokio::net::lookup_host((server, port)),
        )
        .await
        .map_err(|_| anyhow::anyhow!(
            "system getaddrinfo timeout ({SYS_LOOKUP_TIMEOUT:?}) for '{server}' (outbound '{self_tag}')"
        ))??
        .next()
        .ok_or_else(|| anyhow::anyhow!("DNS lookup failed for {server}"))
    }
}

pub async fn resolve_target(target: &Target) -> anyhow::Result<SocketAddr> {
    match target {
        Target::Socket(addr) => Ok(*addr),
        Target::Domain(host, port) => {
            let addr = tokio::net::lookup_host((host.as_str(), *port))
                .await?
                .next()
                .ok_or_else(|| anyhow::anyhow!("DNS lookup failed for {host}"))?;
            Ok(addr)
        }
    }
}

/// 优先用内部 DNS 解析器解析域名，避免走系统 getaddrinfo。
/// 若 resolver 为 None 则退回系统解析（向后兼容）。
pub async fn resolve_target_with_dns(
    target: &Target,
    resolver: Option<&Arc<DnsResolver>>,
) -> anyhow::Result<SocketAddr> {
    match target {
        Target::Socket(addr) => Ok(*addr),
        Target::Domain(host, port) => {
            if let Some(r) = resolver {
                let ip = r.resolve_domain(host).await?;
                Ok(SocketAddr::new(ip, *port))
            } else {
                let addr = tokio::net::lookup_host((host.as_str(), *port))
                    .await?
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("DNS lookup failed for {host}"))?;
                Ok(addr)
            }
        }
    }
}
