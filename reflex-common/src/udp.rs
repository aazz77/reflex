//! 入站/出站共享的 UDP 抽象：数据包与会话句柄。

use std::net::SocketAddr;

use crate::target::Target;

/// 一个入站 UDP 数据包（或 UDP 会话的第一个包），携带原始目标地址。
pub struct InboundUdpPacket {
    /// 数据载荷
    pub data: bytes::Bytes,
    /// 发送方地址（用于回包）
    pub src: SocketAddr,
    /// 真实目标地址
    pub target: Target,
    /// 来自哪个入站 tag
    pub inbound_tag: String,
    /// 嗅探识别出的应用层协议（如 `"dns"`），未嗅探时为 None
    pub sniffed_protocol: Option<String>,
    /// 嗅探识别出的域名（override_destination=false 时不覆盖 target，但保存在此）
    pub sniffed_domain: Option<String>,
    /// 原始 FakeIP 目标地址（参照 sing-box metadata.OriginDestination）。
    ///
    /// 仅在 dispatcher 做 FakeIP 反向查找命中时被设置：原本 `target` 是
    /// `Socket(fakeip, port)`，反向查到域名后被改写为 `Domain(domain, port)`，
    /// 此字段保存原 FakeIP SocketAddr，用于 UDP 回包时把源地址伪装回 fakeip
    /// （参照 sing-box `bufio.NewNATPacketConn` 的写回源地址改写）。
    ///
    /// 出站实现构造回包时应优先使用本字段，缺失时回退到 `target.to_socket_addr_lossy()`。
    pub origin_destination: Option<SocketAddr>,
    /// UDP 会话句柄（用于后续回包）
    pub session: UdpSession,
    /// 后续上行包通道（仅在 dispatcher run_udp_session 里非 None）。
    /// 出站实现收到后应持续从此通道读取并发往服务端，直到通道关闭或超时。
    /// 这保证整个会话共用同一个出站 socket（固定源端口），游戏协议要求此行为。
    ///
    /// 每个元素携带该包的目标 `(Target, Bytes)`：会话按 (src, outbound) 聚合后，
    /// 同一客户端 socket 访问多个目标的包会复用同一条出站连接，因此每包必须
    /// 携带自己的目标地址，出站实现据此构建协议帧（对齐 mihomo natTable 按 src 聚合）。
    pub upstream_rx: Option<tokio::sync::mpsc::Receiver<(Target, bytes::Bytes)>>,
    /// 需要与会话生命周期绑定的守卫对象（ConnGuard / UdpGuard 等）。
    /// 出站实现应将此字段 move 进持久 task，确保连接在 clash API 中保持可见。
    pub lifetime_guards: Vec<Box<dyn std::any::Any + Send>>,
}

/// UDP 会话句柄，入站层持有，用于将出站的回包写回给客户端。
#[derive(Debug, Clone)]
pub struct UdpSession {
    /// 用于回包：(数据, 客户端地址, 伪造源地址=原始目标IP)
    pub reply_tx: tokio::sync::mpsc::Sender<(bytes::Bytes, SocketAddr, SocketAddr)>,
}

