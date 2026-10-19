//! DNS 查询请求类型：TUN hijack / dns-in 入站向解析器投递的统一载体。

use bytes::Bytes;
use std::net::SocketAddr;
use tokio::sync::{mpsc, oneshot};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsQuerySource {
    /// 来自专用 DNS 入站（`dns-in` 监听端口直接接收的 DNS 查询）
    Inbound,
    /// 来自路由层 hijack_dns 规则（流量原本目标是 53 端口，被路由劫持）
    Hijacked,
}

/// 一次 DNS 查询请求，附带回复通道
#[derive(Debug)]
pub struct DnsQuery {
    /// 原始 DNS wire-format 查询报文
    pub message: Bytes,
    /// 查询来源（用于日志）
    pub from: SocketAddr,
    /// 来自哪个 dns-in tag
    pub inbound_tag: String,
    /// 查询来源类型（专用入站 / 路由劫持）
    pub source: DnsQuerySource,
    /// 回复通道：DNS 模块将 wire-format 响应写回此处
    pub reply_tx: oneshot::Sender<Bytes>,
}

pub type DnsQueryTx = mpsc::Sender<DnsQuery>;

