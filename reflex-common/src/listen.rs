//! 入站监听地址解析工具（reflex-common）。
//!
//! 历史上位于 `reflex-lib::inbound`，因 inbound 拆分为「客户端本地入站」
//! （留在 reflex-lib）与「代理协议入站」（迁入 reflex-protocol）后双方共用，
//! 上移至 common。

use std::net::SocketAddr;

/// 将 `listen`（IP 字符串）和 `port` 组合为 `SocketAddr`。
///
/// 支持三种填写方式，语义与 sing-box 完全一致：
///
/// | `listen` 值 | 含义                           | 组合结果           |
/// |-------------|--------------------------------|--------------------|
/// | `0.0.0.0`   | 监听所有 IPv4 接口             | `0.0.0.0:PORT`     |
/// | `127.0.0.1` | 仅本机 IPv4 回环               | `127.0.0.1:PORT`   |
/// | `::`        | 监听所有接口（IPv4 + IPv6）    | `[::]:PORT`        |
/// | `::1`       | 仅本机 IPv6 回环               | `[::1]:PORT`       |
///
/// IPv6 地址会自动加方括号，`format!("{}:{}", "::", port)` 产生的非法格式
/// `:::::PORT` 由此修正。
pub fn parse_listen_addr(listen: &str, port: u16) -> anyhow::Result<SocketAddr> {
    // 先尝试 "host:port" 格式（兼容用户直接填了含端口的字符串）
    let addr_str = if listen.contains(':') && !listen.starts_with('[') {
        // 裸 IPv6 地址（如 "::" 或 "::1"），需要加方括号
        format!("[{listen}]:{port}")
    } else {
        // IPv4 地址或已含方括号的 IPv6（如 "[::1]"）
        format!("{listen}:{port}")
    };
    addr_str
        .parse::<SocketAddr>()
        .map_err(|e| anyhow::anyhow!("invalid listen address '{listen}:{port}': {e}"))
}

/// 解析 `external_controller` 风格的完整地址字符串（含端口）。
///
/// 支持：
/// - `0.0.0.0:9090`
/// - `127.0.0.1:9090`
/// - `[::]:9090`（标准 IPv6 含端口格式）
/// - `:::9090`（用户常见误填，自动修正为 `[::]:9090`）
/// - `:9090`（等价于 `0.0.0.0:9090`，sing-box 支持）
pub fn parse_controller_addr(addr: &str) -> anyhow::Result<SocketAddr> {
    // 标准格式：直接解析
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return Ok(sa);
    }

    // ":PORT" 简写 → "0.0.0.0:PORT"
    if let Some(port_str) = addr.strip_prefix(':') {
        if !port_str.contains(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                return Ok(SocketAddr::from(([0, 0, 0, 0], port)));
            }
        }
    }

    // ":::PORT" 或 "HOST:PORT" 中 HOST 是裸 IPv6 的情况
    // 找最后一个 ':' 分割 host 和 port
    if let Some(colon_pos) = addr.rfind(':') {
        let (host, port_str) = (&addr[..colon_pos], &addr[colon_pos + 1..]);
        if let Ok(port) = port_str.parse::<u16>() {
            // host 是裸 IPv6（含有 ':'）且没有方括号
            let normalized = if host.contains(':') && !host.starts_with('[') {
                format!("[{host}]:{port}")
            } else {
                format!("{host}:{port}")
            };
            if let Ok(sa) = normalized.parse::<SocketAddr>() {
                return Ok(sa);
            }
        }
    }

    Err(anyhow::anyhow!(
        "invalid address '{addr}': expected HOST:PORT, [IPv6]:PORT, or :PORT"
    ))
}

/// 把 IPv4-mapped IPv6 地址转回纯 IPv4 显示。
///
/// 双栈 socket（如 tproxy/redir/mixed/socks/http 监听 `::` + V6ONLY=false）上，
/// 内核会把 IPv4 连接的对端地址以 IPv4-mapped IPv6 形式上报
/// （如 `[::ffff:10.0.0.101]:34488`），日志里显示不直观。
/// 本函数把这种地址转回纯 IPv4；真实 IPv6 地址保持不变。
pub fn display_sockaddr(addr: SocketAddr) -> SocketAddr {
    let ip = match addr.ip() {
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(std::net::IpAddr::V4)
            .unwrap_or(std::net::IpAddr::V6(v6)),
        ip => ip,
    };
    SocketAddr::new(ip, addr.port())
}

#[cfg(test)]
mod addr_tests {
    use super::*;

    // ── parse_listen_addr ──────────────────────────────────────────────────

    #[test]
    fn ipv4_any() {
        let a = parse_listen_addr("0.0.0.0", 7890).unwrap();
        assert_eq!(a.to_string(), "0.0.0.0:7890");
        assert!(a.is_ipv4());
    }

    #[test]
    fn ipv4_loopback() {
        let a = parse_listen_addr("127.0.0.1", 1080).unwrap();
        assert_eq!(a.to_string(), "127.0.0.1:1080");
    }

    #[test]
    fn ipv6_any_bare() {
        // "::" 裸 IPv6，必须自动加方括号
        let a = parse_listen_addr("::", 7890).unwrap();
        assert!(a.is_ipv6());
        assert_eq!(a.port(), 7890);
    }

    #[test]
    fn ipv6_loopback_bare() {
        let a = parse_listen_addr("::1", 7890).unwrap();
        assert!(a.is_ipv6());
        assert_eq!(a.port(), 7890);
    }

    #[test]
    fn invalid_listen_rejected() {
        assert!(parse_listen_addr("not-an-ip", 80).is_err());
    }

    // ── parse_controller_addr ─────────────────────────────────────────────

    #[test]
    fn controller_ipv4() {
        let a = parse_controller_addr("0.0.0.0:9090").unwrap();
        assert_eq!(a.to_string(), "0.0.0.0:9090");
    }

    #[test]
    fn controller_loopback() {
        let a = parse_controller_addr("127.0.0.1:9090").unwrap();
        assert_eq!(a.to_string(), "127.0.0.1:9090");
    }

    #[test]
    fn controller_ipv6_bracketed() {
        // 标准写法 [::]:9090
        let a = parse_controller_addr("[::]:9090").unwrap();
        assert!(a.is_ipv6());
    }

    #[test]
    fn controller_ipv6_bare_triple_colon() {
        // 用户常见误填 :::9090，自动修正为 [::]:9090
        let a = parse_controller_addr(":::9090").unwrap();
        assert!(a.is_ipv6());
        assert_eq!(a.port(), 9090);
    }

    #[test]
    fn controller_shorthand_port_only() {
        // :9090 等价于 0.0.0.0:9090
        let a = parse_controller_addr(":9090").unwrap();
        assert_eq!(a.to_string(), "0.0.0.0:9090");
    }

    #[test]
    fn controller_invalid_rejected() {
        assert!(parse_controller_addr("notanaddr").is_err());
        assert!(parse_controller_addr("0.0.0.0").is_err()); // 缺端口
    }
}
