// ── 多候选匹配辅助函数 ──────────────────────────────────────────────────────

/// 将域名归一化：trim 末尾 '.' + ASCII 小写。
/// 仅在含有大写字母或末尾 '.' 时分配；多数情况（已是规范小写无 FQDN 点）
/// 直接返回 Cow::Borrowed，零分配。
#[inline]
pub fn normalize_domain(d: &str) -> std::borrow::Cow<'_, str> {
    let trimmed = d.trim_end_matches('.');
    if trimmed.bytes().any(|b| b.is_ascii_uppercase()) {
        std::borrow::Cow::Owned(trimmed.to_ascii_lowercase())
    } else {
        std::borrow::Cow::Borrowed(trimmed)
    }
}
