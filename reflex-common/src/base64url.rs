use anyhow::Context;

// ── base64 解码（base64url 优先，兼容标准 base64）───────────────────────────

pub fn base64_url_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    use base64::Engine;
    let s = s.trim();
    if let Ok(v) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s) {
        return Ok(v);
    }
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .context("base64 decode failed")
}
