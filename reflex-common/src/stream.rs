//! 入站/出站共享的连接抽象：携带原始目标地址的 TCP 连接与可嗅探流。

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};

use crate::outbound::AsyncReadWrite;
use crate::proxy_common::duplicate_tcp_stream;
use crate::target::Target;

// ── 共享抽象 ──────────────────────────────────────────────────────────────────

/// 一条已建立的入站 TCP 连接，携带原始目标地址。
/// 路由层拿到它后决定走哪个出站。
pub struct InboundTcpStream {
    /// TCP 流（可能携带嗅探时 peek 出的前缀字节）
    pub stream: SniffedStream,
    /// 连接的真实目标（域名或 IP:Port）
    pub target: Target,
    /// 来自哪个入站 tag
    pub inbound_tag: String,
    /// 嗅探识别出的应用层协议（如 `"dns"`），未嗅探时为 None
    pub sniffed_protocol: Option<String>,
    /// 嗅探识别出的域名（override_destination=false 时不覆盖 target，但保存在此）
    pub sniffed_domain: Option<String>,
}

// ── SniffedStream ─────────────────────────────────────────────────────────────

/// 对 [`TcpStream`] 的薄包装，允许在嗅探时将 peek 出的字节归还回去，
/// 使后续的出站读取对这些字节无感知。
///
/// 读取顺序：先消耗 `prefix`，再透传 `inner`。
/// 写入、关闭等操作直接委托给 `inner`。
///
/// **内层流已泛化为 `Box<dyn AsyncReadWrite>`**：除了裸 TCP（socks/http/mixed
/// 等入站），还承载 TLS 解密后的协议流（vless/vmess/trojan 服务端入站在
/// TLS 握手 + 协议头解析后，把解密流装箱交给 dispatcher 路由）。对端地址
/// 在构造时一次性捕获（TLS 场景由入站层传入解密前的真实地址），后续
/// `peer_addr()` 不再触碰内核。
pub struct SniffedStream {
    /// 嗅探阶段 peek 出的字节（未嗅探时为空）
    pub prefix: Bytes,
    pub inner: Box<dyn AsyncReadWrite>,
    /// 原始 TCP 流克隆（仅当底层是 TCP 时非 None）。
    /// 供 Drop-RST（SO_LINGER=0）与 reject_tcp 的 RST 语义使用；TLS 场景
    /// 仍可提供（TLS accept 前的 TcpStream 可 try_clone），非 TCP 场景为 None。
    raw_tcp: Option<TcpStream>,
    /// 构造时捕获的对端地址
    peer: SocketAddr,
    /// 实时流量计数器（可选）：由 `handle_tcp_live` 注入，在 poll_read/poll_write 里更新
    pub live_down: Option<std::sync::Arc<portable_atomic::AtomicI64>>,
    pub live_up: Option<std::sync::Arc<portable_atomic::AtomicI64>>,
    /// T3：Drop 时是否发 RST（SO_LINGER=0）。由 `handle_tcp_live` 在交给
    /// 出站前武装；一旦有成功的数据收发（即拨号已成功）自动解除。若在
    /// 解除前流被 drop（出站拨号失败），内核发 RST 而非 FIN，客户端立即
    /// 感知拒绝而非挂到超时（对齐 sing-box 拨号失败 → tun.ErrReset）。
    rst_on_drop: bool,
}

impl SniffedStream {
    /// 直接从裸 [`TcpStream`] 创建，prefix 为空（未嗅探）。
    pub fn new(stream: TcpStream) -> Self {
        let peer = stream.peer_addr().unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0)));
        let raw_tcp = duplicate_tcp_stream(&stream).ok();
        Self {
            prefix: Bytes::new(),
            inner: Box::new(stream),
            raw_tcp,
            peer,
            live_down: None,
            live_up: None,
            rst_on_drop: false,
        }
    }

    /// 从已解密/已解协议的动态流创建（vless/vmess/trojan 服务端入站用）。
    ///
    /// - `inner`：TLS 解密 + 协议层处理后的流（如 VLESS 请求头消费后的 TlsStream）
    /// - `peer`：解密前捕获的真实客户端地址（供路由/统计使用）
    /// - `raw_tcp`：TLS accept 前的原始 TcpStream（若可 try_clone），保留
    ///   Drop-RST 与 reject RST 语义
    pub fn from_encrypted(
        inner: Box<dyn AsyncReadWrite>,
        peer: SocketAddr,
        raw_tcp: Option<TcpStream>,
    ) -> Self {
        Self {
            prefix: Bytes::new(),
            inner,
            raw_tcp,
            peer,
            live_down: None,
            live_up: None,
            rst_on_drop: false,
        }
    }

    /// 原始 TCP 流（仅 TCP 底层非 None），供 reject 路径的 SO_LINGER=0 RST 使用。
    pub fn raw_tcp(&self) -> Option<&TcpStream> {
        self.raw_tcp.as_ref()
    }

    /// 武装 Drop-RST：此后若流在解除前被 drop（出站拨号失败），内核发 RST。
    /// 成功的数据收发会自动解除（见 poll_read/poll_write）。
    pub fn arm_rst_on_drop(&mut self) {
        self.rst_on_drop = true;
    }

    /// 注入实时计数器，后续每次 read/write 都会更新对应原子值。
    pub fn set_live_counters(
        &mut self,
        live_up: std::sync::Arc<portable_atomic::AtomicI64>,
        live_down: std::sync::Arc<portable_atomic::AtomicI64>,
    ) {
        self.live_up = Some(live_up);
        self.live_down = Some(live_down);
    }

    /// 嗅探完成后，将 peek 出的字节作为 prefix 归还。
    pub fn prepend(&mut self, data: Bytes) {
        if data.is_empty() {
            return;
        }
        if self.prefix.is_empty() {
            self.prefix = data;
        } else {
            // 极少见：多次 prepend，直接拼接
            let mut buf = bytes::BytesMut::with_capacity(self.prefix.len() + data.len());
            buf.extend_from_slice(&self.prefix);
            buf.extend_from_slice(&data);
            self.prefix = buf.freeze();
        }
    }
    /// 返回构造时捕获的对端地址（不再触碰内核，恒为 Ok）。
    pub fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        Ok(self.peer)
    }
}

impl AsyncRead for SniffedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let amt = self.prefix.len().min(buf.remaining());
            buf.put_slice(&self.prefix[..amt]);
            self.prefix.advance(amt);
            if let Some(c) = &self.live_down {
                c.fetch_add(amt as i64, std::sync::atomic::Ordering::Relaxed);
            }
            return Poll::Ready(Ok(()));
        }
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let n = buf.filled().len() - before;
            if n > 0 {
                if let Some(c) = &self.live_down {
                    c.fetch_add(n as i64, std::sync::atomic::Ordering::Relaxed);
                }
                // T3：已读到客户端数据 → 拨号必然已成功，解除 Drop-RST
                self.rst_on_drop = false;
            }
        }
        result
    }
}

impl Drop for SniffedStream {
    fn drop(&mut self) {
        if self.rst_on_drop {
            // SO_LINGER=0 → 内核关闭时发 RST 而非 FIN（linger 0 不阻塞线程）。
            // 对齐 sing-box 拨号失败路径的 tun.ErrReset。
            // 仅底层是 TCP 时可行；TLS 流在 raw_tcp 上操作（linger 作用于
            // 底层 socket，TLS 层无需感知）。
            #[allow(deprecated)]
            if let Some(raw) = self.raw_tcp.as_ref() {
                let _ = raw.set_linger(Some(std::time::Duration::ZERO));
            }
        }
    }
}

impl AsyncWrite for SniffedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = &result {
            if *n > 0 {
                // T3：已成功向客户端写出数据 → 解除 Drop-RST
                self.rst_on_drop = false;
            }
            if let Some(c) = &self.live_up {
                c.fetch_add(*n as i64, std::sync::atomic::Ordering::Relaxed);
            }
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

