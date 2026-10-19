//! 协议层：各代理协议的共享原语 + inbound（服务端）/ outbound（客户端）实现，
//! 以及传输层（transport）与加密层（tls）。
//!
//! 目录组织（按协议纵切，一个协议一个文件夹）：
//! - `<proto>/mod.rs`：inbound 与 outbound 共享的编解码原语（cipher 枚举、KDF、
//!   AEAD 编解码器、地址编解码、帧常量），不含连接管理。
//! - `<proto>/inbound.rs`：服务端入站，解析出目标后经
//!   `InboundTcpStream`/`InboundUdpPacket` 通道交给 reflex-lib 的 dispatcher
//!   按路由规则选择出站，不直接拨号。
//! - `<proto>/outbound.rs`：客户端出站，共用 [`crate::common`] 基建
//!   （relay/地址解析/CountedStream）、[`crate::transport`]（ws/grpc/xhttp）
//!   与 [`crate::tls`]（utls/ech/reality）。
//! - [`crate::common`]：出站共享基建 + 代理组（selector/urltest）+ smux。
//! - [`crate::transport`]：v2ray 传输层，服务端与客户端对偶实现同文件。
//! - [`crate::tls`]：TLS 加密层（客户端 connector/ech/utls/reality + 服务端 acceptor）。
//!
//! 客户端本地入站（socks/http/mixed/tproxy/redir/dns）不属于代理协议，
//! 保留在 reflex-lib。
//!
//! 当前覆盖：vless / vmess / trojan / shadowsocks / tuic / hysteria2 / anytls /
//! naive / shadowquic / wireguard / socks / http，以及 direct / block /
//! ssh / tailscale。后续新增协议按同样模式建文件夹。

pub mod anytls;
pub mod block;
pub mod common;
pub mod direct;
pub mod hysteria2;
pub mod http;
pub mod naive;
pub mod shadowquic;
pub mod shadowsocks;
pub mod socks;
pub mod tls;
pub mod transport;
pub mod trojan;
pub mod tuic;
pub mod vless;
pub mod vmess;
pub mod wireguard;

#[cfg(feature = "ssh")]
pub mod ssh;

#[cfg(feature = "tailscale")]
pub mod tailscale;
