//! Plain-language descriptions of Java exceptions for non-developers.

use std::sync::LazyLock;

use anycasted_core::models::ThrownException;
use anycasted_core::text::excerpt;
use regex::Regex;

static NULL_LOCAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"because "([^"]+)" is null"#).expect("valid regex"));
static NULL_RETURN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"because the return value of "([^"]+)" is null"#).expect("valid regex")
});
static INPUT_STRING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"For input string: "([^"]*)""#).expect("valid regex"));

/// The missing value named by a Java "helpful NullPointerException" message, e.g.
/// `this.chat` from `Cannot invoke "..." because "this.chat" is null`.
pub fn null_reference(exc: &ThrownException) -> Option<String> {
    if exc.simple_name() != "NullPointerException" {
        return None;
    }
    let msg = exc.message.as_deref()?;
    if let Some(c) = NULL_RETURN.captures(msg) {
        let method = c[1].rsplit('.').next().unwrap_or(&c[1]);
        return Some(format!("the result of {method}"));
    }
    let name = NULL_LOCAL.captures(msg)?.get(1)?.as_str();
    // `<local4>` carries no meaning for a reader.
    (!name.starts_with('<')).then(|| name.to_owned())
}

/// A short, plain-language description of what went wrong, written to complete a
/// sentence such as "Foo hit an error: …".
pub fn error_hint(exc: &ThrownException) -> String {
    let msg = exc.message.as_deref().map(|m| excerpt(m, 120).into_owned());
    let simple = exc.simple_name();
    let simple = simple.rsplit('$').next().unwrap_or(simple);
    match simple {
        "NullPointerException" => match null_reference(exc) {
            Some(r) => format!("a value it needed (`{r}`) was missing"),
            None => "a value it needed was missing".into(),
        },
        "IllegalArgumentException" => match msg {
            Some(m) => format!("it was given a value it can't use ({m})"),
            None => "it was given a value it can't use".into(),
        },
        "IllegalStateException" => match msg {
            Some(m) => format!("something was in a state it didn't expect ({m})"),
            None => "something was in a state it didn't expect".into(),
        },
        "ConcurrentModificationException" => {
            "two parts of its code changed the same data at the same time".into()
        }
        "ArrayIndexOutOfBoundsException"
        | "IndexOutOfBoundsException"
        | "StringIndexOutOfBoundsException" => "it tried to read past the end of a list".into(),
        "ClassCastException" => "it mixed up two different kinds of data".into(),
        "NumberFormatException" => match exc
            .message
            .as_deref()
            .and_then(|m| INPUT_STRING.captures(m))
        {
            Some(c) => format!("it expected a number but found `{}`", &c[1]),
            None => "it expected a number but found something else".into(),
        },
        "UnsupportedOperationException" => "it tried something that isn't supported".into(),
        "StackOverflowError" => "it got stuck calling itself over and over".into(),
        "OutOfMemoryError" => "the server ran out of memory".into(),
        _ => match msg {
            Some(m) => format!("an unexpected error ({simple}: {m})"),
            None => format!("an unexpected error ({simple})"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anycasted_core::models::ThrowableRelation;

    fn exc(class: &str, msg: Option<&str>) -> ThrownException {
        ThrownException {
            line: 1,
            relation: ThrowableRelation::Thrown,
            class: class.into(),
            message: msg.map(Into::into),
            frames: Vec::new(),
            omitted_frames: 0,
        }
    }

    #[test]
    fn helpful_npe() {
        let e = exc(
            "java.lang.NullPointerException",
            Some(
                r#"Cannot invoke "net.milkbowl.vault.chat.Chat.getPlayerPrefix(org.bukkit.OfflinePlayer)" because "this.chat" is null"#,
            ),
        );
        assert_eq!(null_reference(&e).as_deref(), Some("this.chat"));
        assert_eq!(
            error_hint(&e),
            "a value it needed (`this.chat`) was missing"
        );
        let local = exc(
            "java.lang.NullPointerException",
            Some(r#"Cannot invoke "x()" because "<local1>" is null"#),
        );
        assert_eq!(null_reference(&local), None);
    }

    #[test]
    fn number_format() {
        let e = exc(
            "java.lang.NumberFormatException",
            Some(r#"For input string: "ten""#),
        );
        assert_eq!(error_hint(&e), "it expected a number but found `ten`");
    }
}
