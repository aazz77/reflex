//! reflex 共享词汇层。
//!
//! 跨 `reflex-inbound` / `reflex-outbound` / `reflex-dns` / `reflex-netstack`
//! 复用的 trait 与类型。本 crate 不依赖 workspace 内其他 crate（最底层）。

pub mod base64url;
pub mod cache_file;
pub mod clash_mode;
pub mod dns_query;
pub mod domain;
pub mod icmp;
pub mod interface_finder;
pub mod listen;
pub mod outbound;
pub mod proxy_common;
pub mod shutdown;
pub mod stream;
pub mod target;
pub mod tls;
pub mod udp;
