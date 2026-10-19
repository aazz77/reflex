//! ICMP 路由决策抽象。
//!
//! `reflex-netstack` 的 ICMP forwarder 只依赖本 trait，不直接依赖
//! `reflex-lib` 的 Router / OutboundManager；由 lib 侧适配器
//! （`reflex_lib::app::icmp_router::IcmpRouteAdapter`）把
//! `Router::route_icmp` + `OutboundManager` 的 ICMP 支持判断桥接到本 trait。

use std::net::IpAddr;

/// 对一次 ICMP echo 的路由决策（netstack 侧视角）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpAction {
    /// 放行：调用方走 raw socket 直连转发。
    Forward,
    /// 拒绝（默认方法）：回复 ICMP 主机不可达。
    RejectDefault,
    /// 拒绝（reply 方法）：回显应答（假装主机存活）。
    RejectReply,
    /// 静默丢弃。
    Drop,
}

/// ICMP 路由策略提供者。
///
/// 对齐 sing-box 1.13.0 `network: "icmp"` 规则语义：
/// - `route` → direct 出站：放行（raw socket 转发）
/// - `route` → 非直连出站：丢弃（代理出站不支持 ICMP）
/// - `reject(default)`：回复主机不可达
/// - `reject(reply)`：回显应答
/// - `reject(drop)` / `block`：静默丢弃
///
/// `inbound_tag` 由实现方在创建适配器时绑定（一个 TUN 入站一个适配器），
/// 因此 trait 方法签名里不再传递它。
pub trait IcmpRouter: Send + Sync + 'static {
    /// 决策一次 ICMP echo 请求的处置方式。
    fn route_icmp(&self, src: IpAddr, dst: IpAddr) -> IcmpAction;
}
