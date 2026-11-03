//! Java throwables and stack traces.

use serde::Serialize;

/// How a throwable relates to the previous one in a printed chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThrowableRelation {
    /// The outermost throwable of a chain.
    Thrown,
    /// Introduced by `Caused by:`.
    CausedBy,
    /// Introduced by `Suppressed:`.
    Suppressed,
}

/// One `at ...` stack frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StackFrame {
    /// Source line number of the frame.
    pub line: u64,
    /// Java module / class loader prefix (`java.base`, `java.base@17.0.1`, `app//`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    /// Fully qualified class name.
    pub class: String,
    /// Method name.
    pub method: String,
    /// Source file name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Source file line number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_number: Option<u32>,
    /// Whether the frame is a native method.
    pub native: bool,
    /// Archive the class was loaded from, as printed by log4j (`~[Foo-1.0.jar:?]`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jar: Option<String>,
}

impl StackFrame {
    /// `class.method`.
    pub fn qualified_method(&self) -> String {
        format!("{}.{}", self.class, self.method)
    }
}

/// One throwable within a chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ThrownException {
    /// Source line number of the throwable header.
    pub line: u64,
    /// Relation to the previous throwable.
    pub relation: ThrowableRelation,
    /// Fully qualified class name (may be unqualified when printed that way).
    pub class: String,
    /// Message, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Retained frames.
    #[serde(skip)]
    pub frames: Vec<StackFrame>,
    /// Frames not retained, plus frames elided by Java (`... 12 more`).
    #[serde(skip)]
    pub omitted_frames: u32,
}

impl ThrownException {
    /// The class name without its package.
    pub fn simple_name(&self) -> &str {
        simple_class_name(&self.class)
    }

    /// Whether this throwable is of class `name`.
    ///
    /// `name` may be fully qualified (`java.lang.NullPointerException`), a simple name
    /// (`NullPointerException`) or a nested-class simple name
    /// (`AnnotatedConnectException` matches `io.netty.channel.AbstractChannel$AnnotatedConnectException`).
    pub fn is(&self, name: &str) -> bool {
        if name.contains('.') {
            return self.class == name;
        }
        let simple = self.simple_name();
        simple == name || simple.rsplit('$').next() == Some(name)
    }

    /// Lower-cased message, or an empty string.
    pub fn message_lower(&self) -> String {
        self.message.as_deref().unwrap_or("").to_ascii_lowercase()
    }
}

/// Returns the part of a class name after the last `.`.
pub fn simple_class_name(class: &str) -> &str {
    class.rsplit('.').next().unwrap_or(class)
}

/// A printed throwable and its `Caused by:` / `Suppressed:` chain.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct ExceptionChain {
    /// Throwables in printed order; `exceptions[0]` is the outermost.
    pub exceptions: Vec<ThrownException>,
}

impl ExceptionChain {
    /// The outermost throwable.
    pub fn top(&self) -> Option<&ThrownException> {
        self.exceptions.first()
    }

    /// Throwables on the causal path (excluding suppressed ones), outermost first.
    pub fn causal(&self) -> impl Iterator<Item = &ThrownException> {
        self.exceptions
            .iter()
            .filter(|e| e.relation != ThrowableRelation::Suppressed)
    }

    /// The innermost cause on the causal path.
    pub fn root_cause(&self) -> Option<&ThrownException> {
        self.causal().last()
    }

    /// Whether any throwable in the chain has stack frames.
    pub fn has_frames(&self) -> bool {
        self.exceptions.iter().any(|e| !e.frames.is_empty())
    }

    /// All frames of all throwables.
    pub fn frames(&self) -> impl Iterator<Item = &StackFrame> {
        self.exceptions.iter().flat_map(|e| e.frames.iter())
    }
}
