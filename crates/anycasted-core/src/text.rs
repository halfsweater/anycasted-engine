//! Text utilities: bounded excerpts, message normalization and stable fingerprints.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt::Write as _;

/// Returns at most `max_chars` characters of `s`, appending `…` when shortened.
pub fn excerpt(s: &str, max_chars: usize) -> Cow<'_, str> {
    match s.char_indices().nth(max_chars) {
        None => Cow::Borrowed(s),
        Some((idx, _)) => {
            let mut out = String::with_capacity(idx + 3);
            out.push_str(&s[..idx]);
            out.push('…');
            Cow::Owned(out)
        }
    }
}

/// Normalizes a free-form message so that messages differing only in variable data
/// (numbers, ids, coordinates, UUIDs, hex addresses) produce the same string.
///
/// Every alphanumeric word that contains at least one ASCII digit is replaced by `#`;
/// whitespace runs are collapsed. The result is capped at `max_chars` characters.
pub fn normalize_message(s: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max_chars));
    let mut word = String::new();
    let mut chars = 0usize;
    let mut last_space = false;

    let flush = |word: &mut String, out: &mut String, chars: &mut usize| {
        if word.is_empty() {
            return;
        }
        if word.chars().any(|c| c.is_ascii_digit()) {
            out.push('#');
            *chars += 1;
        } else {
            *chars += word.chars().count();
            out.push_str(word);
        }
        word.clear();
    };

    for c in s.chars() {
        if chars >= max_chars {
            break;
        }
        if c.is_alphanumeric() || c == '_' {
            word.push(c);
            continue;
        }
        flush(&mut word, &mut out, &mut chars);
        if c.is_whitespace() {
            if !last_space && !out.is_empty() {
                out.push(' ');
                chars += 1;
            }
            last_space = true;
        } else {
            out.push(c);
            chars += 1;
            last_space = false;
        }
    }
    flush(&mut word, &mut out, &mut chars);
    let trimmed = out.trim_end().len();
    out.truncate(trimmed);
    out
}

/// Incremental 64-bit FNV-1a hasher.
///
/// Used instead of `std::hash` because fingerprints are part of the public report and
/// must be stable across Rust versions, platforms and process runs.
#[derive(Debug, Clone)]
pub struct Fingerprinter(u64);

impl Default for Fingerprinter {
    fn default() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }
}

impl Fingerprinter {
    /// Creates a new hasher.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds a string component. Components are separated so that `("ab","c")` and
    /// `("a","bc")` hash differently.
    pub fn write(&mut self, part: &str) -> &mut Self {
        for &b in part.as_bytes() {
            self.0 ^= u64::from(b);
            self.0 = self.0.wrapping_mul(0x0100_0000_01b3);
        }
        self.0 ^= 0x1f;
        self.0 = self.0.wrapping_mul(0x0100_0000_01b3);
        self
    }

    /// Returns the fingerprint as 16 lowercase hex characters.
    pub fn finish_hex(&self) -> String {
        let mut s = String::with_capacity(16);
        let _ = write!(s, "{:016x}", self.0);
        s
    }
}

/// Renders a user-facing template.
///
/// * `{name}` — the variable's value.
/// * `{name|fallback}` — the value, or `fallback` when the variable is unknown.
/// * `[[ ... ]]` — an optional segment, dropped unless every variable inside it without
///   a fallback is known. Segments do not nest.
///
/// Unknown variables without fallback outside a segment render as nothing (rule
/// validation rejects such templates). Whitespace is normalized.
pub fn render_template(template: &str, vars: &BTreeMap<String, String>) -> String {
    let mut out = String::with_capacity(template.len() + 32);
    let mut rest = template;
    while let Some(start) = rest.find("[[") {
        out.push_str(&substitute(&rest[..start], vars).unwrap_or_else(|s| s));
        let after = &rest[start + 2..];
        let end = after.find("]]").unwrap_or(after.len());
        if let Ok(segment) = substitute(&after[..end], vars) {
            out.push_str(&segment);
        }
        rest = after.get(end + 2..).unwrap_or("");
    }
    out.push_str(&substitute(rest, vars).unwrap_or_else(|s| s));
    tidy(&out.split_whitespace().collect::<Vec<_>>().join(" "))
}

/// Removes a space left before `.`, `,` or `:` by an empty optional segment, but only
/// where the punctuation ends a word (so `./crash-reports` stays intact).
fn tidy(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    for (i, &c) in chars.iter().enumerate() {
        let next = chars.get(i + 1).copied();
        let after = chars.get(i + 2).copied();
        let drop_space = c == ' '
            && matches!(next, Some('.' | ',' | ':'))
            && after.is_none_or(char::is_whitespace);
        if !drop_space {
            out.push(c);
        }
    }
    out
}

/// Substitutes variables; `Err` (carrying the partial text) if a variable without
/// fallback is unknown.
fn substitute(text: &str, vars: &BTreeMap<String, String>) -> Result<String, String> {
    let mut out = String::with_capacity(text.len());
    let mut complete = true;
    let mut rest = text;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            out.push_str(&rest[open..]);
            rest = "";
            break;
        };
        let spec = &after[..close];
        let (name, fallback) = match spec.split_once('|') {
            Some((n, f)) => (n.trim(), Some(f)),
            None => (spec.trim(), None),
        };
        match (vars.get(name), fallback) {
            (Some(v), _) => out.push_str(v),
            (None, Some(f)) => out.push_str(f),
            (None, None) => complete = false,
        }
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    if complete { Ok(out) } else { Err(out) }
}

/// Problems with a template: unbalanced brackets, or variables outside an optional
/// segment that have no fallback.
pub fn template_issues(template: &str) -> Vec<String> {
    let mut issues = Vec::new();
    let mut outside = String::new();
    let mut rest = template;
    while let Some(start) = rest.find("[[") {
        outside.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find("]]") {
            Some(end) => rest = &after[end + 2..],
            None => {
                issues.push("unterminated `[[`".into());
                rest = "";
            }
        }
    }
    outside.push_str(rest);
    if outside.contains("]]") {
        issues.push("unmatched `]]`".into());
    }
    let mut rest = outside.as_str();
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            issues.push("unterminated `{`".into());
            break;
        };
        let spec = &after[..close];
        if !spec.contains('|') {
            issues.push(format!(
                "variable `{spec}` needs a fallback or an optional segment"
            ));
        }
        rest = &after[close + 1..];
    }
    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excerpt_respects_char_boundaries() {
        assert_eq!(excerpt("héllo", 10), "héllo");
        assert_eq!(excerpt("héllo", 2), "hé…");
    }

    #[test]
    fn normalization_removes_variable_data() {
        let a = normalize_message("Task #123 for Foo v1.2 failed at x=10, z=-4", 200);
        let b = normalize_message("Task #987 for Foo v1.3 failed at x=99, z=-1", 200);
        assert_eq!(a, b);
        assert!(a.contains("Foo"));
    }

    #[test]
    fn templates() {
        let mut vars = BTreeMap::new();
        vars.insert("plugin".to_owned(), "Foo".to_owned());
        assert_eq!(
            render_template("{plugin|A plugin} failed", &vars),
            "Foo failed"
        );
        assert_eq!(
            render_template("{dep|Something} is missing", &vars),
            "Something is missing"
        );
        assert_eq!(
            render_template(
                "Port in use[[ (port {port})]]. [[Ask {plugin}'s author.]]",
                &vars
            ),
            "Port in use. Ask Foo's author."
        );
        assert_eq!(render_template("[[{port}]]", &vars), "");
        assert_eq!(
            render_template("Open ./crash-reports [[{port}]].", &vars),
            "Open ./crash-reports."
        );
        assert!(template_issues("{plugin|x} [[{port}]]").is_empty());
        assert_eq!(template_issues("{plugin} [[x").len(), 2);
    }

    #[test]
    fn fingerprint_is_stable() {
        let fp = Fingerprinter::new().write("a").write("b").finish_hex();
        assert_eq!(fp, Fingerprinter::new().write("a").write("b").finish_hex());
        assert_ne!(fp, Fingerprinter::new().write("ab").finish_hex());
        assert_eq!(fp.len(), 16);
    }
}
