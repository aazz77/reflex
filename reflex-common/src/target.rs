//! 连接目标：域名或 IP。

use std::net::SocketAddr;

/// 连接目标：域名或 IP
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum Target {
    /// 域名 + 端口（来自 SOCKS5/HTTP CONNECT 握手，或 DNS 嗅探）
    Domain(String, u16),
    /// IP + 端口（来自 TProxy 或已解析）
    Socket(SocketAddr),
}

impl Target {
    pub fn port(&self) -> u16 {
        match self {
            Self::Domain(_, p) => *p,
            Self::Socket(a) => a.port(),
        }
    }

    pub fn host(&self) -> String {
        match self {
            Self::Domain(d, _) => d.clone(),
            Self::Socket(a) => a.ip().to_string(),
        }
    }

    /// 将 Target 转为 SocketAddr，Domain 类型使用 0.0.0.0 占位（仅用于回包伪造源地址场景）
    pub fn to_socket_addr_lossy(&self) -> SocketAddr {
        match self {
            Self::Socket(a) => *a,
            Self::Domain(_, p) => SocketAddr::from(([0, 0, 0, 0], *p)),
        }
    }
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Domain(d, p) => write!(f, "{d}:{p}"),
            Self::Socket(a) => write!(f, "{a}"),
        }
    }
}

