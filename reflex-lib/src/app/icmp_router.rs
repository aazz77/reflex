//! TUN 入站 ICMP 路由策略适配器。
//!
//! `reflex-netstack` 只认识 `reflex_common::icmp::IcmpRouter` 这个 trait，
//! 不直接依赖本 crate 的 `Router` / `OutboundManager`（否则 netstack → lib
//! 与 lib → netstack 会成环）。这里把 lib 侧的路由决策桥接到该 trait：
//!
//! - `Router::route_icmp` 给出 `RouteAction`
//! - `OutboundManager` 给出 `route` 动作指向的出站是否支持 ICMP
//!
//! 组合后收敛为 netstack 需要的四种处置：`Forward / RejectDefault /
//! RejectReply / Drop`。

use std::{net::IpAddr, sync::Arc};

use reflex_common::icmp::{IcmpAction, IcmpRouter};
use reflex_config::route::RejectMethod;
use tracing::debug;

use crate::{
    app::outbound_mgr::OutboundManager,
    router::{RouteAction, Router},
};

/// 把一个 TUN 入站的 (Router, OutboundManager, inbound_tag) 三元组包装成
/// netstack 可直接注入的 ICMP 路由策略。
pub struct IcmpRouteAdapter {
    router: Arc<Router>,
    outbound_mgr: Arc<OutboundManager>,
    /// 入站 tag：传给路由器做 `inbound` 条件匹配。
    inbound_tag: Arc<String>,
}

impl IcmpRouteAdapter {
    pub fn new(
        router: Arc<Router>,
        outbound_mgr: Arc<OutboundManager>,
        inbound_tag: Arc<String>,
    ) -> Self {
        Self {
            router,
            outbound_mgr,
            inbound_tag,
        }
    }

    /// 判断出站是否支持 ICMP：仅 `direct` 出站支持（对齐 sing-box 中
    /// `outbound.Network()` 含 `NetworkICMP` 的语义——仅 direct/wireguard/
    /// tailscale 注册了 ICMP，reflex 的 raw socket 转发等价于 direct）。
    fn outbound_supports_icmp(&self, tag: &str) -> bool {
        match self.outbound_mgr.get(tag) {
            Some(ob) => ob.status().type_name == "Direct",
            None => {
                // 出站不存在：交由默认转发路径（会因 socket 连接失败自然丢弃），
                // 避免路由配置滞后于出站注册时把所有 ping 都拦掉。
                debug!(outbound = %tag, "tun(icmp): route outbound not found, falling through");
                true
            }
        }
    }
}

impl IcmpRouter for IcmpRouteAdapter {
    fn route_icmp(&self, src: IpAddr, dst: IpAddr) -> IcmpAction {
        let (action, _, _, _) = self.router.route_icmp(&self.inbound_tag, Some(src), dst);
        match action {
            RouteAction::Outbound(tag) => {
                if self.outbound_supports_icmp(tag) {
                    IcmpAction::Forward
                } else {
                    tracing::warn!(
                        outbound = %tag,
                        src = %src,
                        dst = %dst,
                        "tun(icmp): route outbound does not support icmp, dropping"
                    );
                    IcmpAction::Drop
                }
            }
            RouteAction::Reject { method } => match method {
                RejectMethod::Default => IcmpAction::RejectDefault,
                RejectMethod::Reply => IcmpAction::RejectReply,
                RejectMethod::Drop => IcmpAction::Drop,
            },
            RouteAction::Block => IcmpAction::Drop,
            RouteAction::DnsOut => IcmpAction::Drop,
            // sniff/resolve 不应出现（route_icmp 已跳过），防御性处理：放行
            RouteAction::Sniff { .. } | RouteAction::Resolve { .. } => IcmpAction::Forward,
        }
    }
}
