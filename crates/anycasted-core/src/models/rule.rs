//! Rule metadata and raw detection hits.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::Serialize;

use super::finding::{
    Category, Classification, Evidence, Implication, Occurrence, Severity, Subject,
};

/// How a rule's hits combine with other hits from the same log entry.
///
/// Minecraft servers often print a *context* message ("Error occurred while enabling
/// Foo") followed by the exception that explains it. Reporting both as separate
/// problems is noise, so hits from one log entry are merged:
///
/// * a [`Specific`](RuleRole::Specific) cause absorbs the context (its plugin, its note)
///   and generic causes are dropped;
/// * without a specific cause, the context absorbs generic causes (their exception
///   becomes a detail of the context finding).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleRole {
    /// A diagnosis in its own right (missing dependency, out of memory, ...).
    #[default]
    Specific,
    /// A message describing *where* something failed (plugin enable, event, task).
    Context,
    /// An exception class that says little on its own (NullPointerException, ...).
    GenericCause,
}

/// Static description of a detection rule.
///
/// Every rule — built-in or user-supplied — carries this metadata so findings are
/// self-describing and the rule catalog can be exported.
///
/// User-facing texts (`user_title`, `explanation`, `recommendations`, `context_note`)
/// are **templates**: `{name}` inserts a variable extracted from the log (plugin name,
/// port, missing class, ...), `{name|fallback}` uses `fallback` when the variable is
/// unknown, and `[[ ... ]]` marks an optional segment that is dropped unless every
/// variable inside it is known. See [`crate::text::render_template`].
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RuleMeta {
    /// Unique, stable identifier (`JAVA-NULL-POINTER`).
    pub id: String,
    /// Category.
    pub category: Category,
    /// Default severity (rules may adjust per hit, e.g. by log level).
    pub severity: Severity,
    /// Default classification.
    pub classification: Classification,
    /// Default confidence; see [`super::Finding`].
    pub confidence: f32,
    /// Merge behavior within one log entry.
    pub role: RuleRole,
    /// Technical title (for support staff and the rule catalog).
    pub title: String,
    /// Technical description.
    pub description: String,
    /// What the input must contain for the rule to fire.
    pub evidence_requirement: String,
    /// Plain-language title template, e.g. `{plugin|A plugin} needs {dependency}`.
    pub user_title: String,
    /// Plain-language "what happened" template.
    pub explanation: String,
    /// Plain-language, ordered fix-step templates.
    pub recommendations: Vec<String>,
    /// For context rules: sentence added to the finding that absorbs this context,
    /// e.g. `Because of this, {plugin} is disabled.`
    pub context_note: Option<String>,
    /// Lower-case phrases that indicate the problem resolved itself (e.g. a database
    /// reconnecting). Matched against later log entries of the same plugin.
    pub recovery_markers: Vec<String>,
    /// Whether a plugin logger tag on the matched line names the finding's plugin.
    /// Disabled for rules where the reporting plugin is not the subject (e.g. a
    /// monitoring plugin printing TPS).
    pub attribute_logger_tag: bool,
}

impl RuleMeta {
    /// Creates rule metadata. Intended for rule definitions:
    ///
    /// ```
    /// use anycasted_core::models::{Category, Classification, RuleMeta, Severity};
    /// let meta = RuleMeta::new("EXAMPLE-RULE", Category::Plugin, Severity::Warning)
    ///     .title("Example")
    ///     .description("Technical explanation.")
    ///     .evidence("A line containing `example`.")
    ///     .user_title("{plugin|A plugin} did something odd")
    ///     .explain("Plain-language explanation.")
    ///     .fix(&["Do something.", "[[Ask the author of {plugin}.]]"]);
    /// assert_eq!(meta.id, "EXAMPLE-RULE");
    /// ```
    pub fn new(id: &str, category: Category, severity: Severity) -> Self {
        Self {
            id: id.to_owned(),
            category,
            severity,
            classification: Classification::Observed,
            confidence: 1.0,
            role: RuleRole::Specific,
            title: String::new(),
            description: String::new(),
            evidence_requirement: String::new(),
            user_title: String::new(),
            explanation: String::new(),
            recommendations: Vec::new(),
            context_note: None,
            recovery_markers: Vec::new(),
            attribute_logger_tag: true,
        }
    }

    /// Sets the technical title.
    pub fn title(mut self, title: &str) -> Self {
        self.title = title.to_owned();
        self
    }

    /// Sets the technical description.
    pub fn description(mut self, description: &str) -> Self {
        self.description = description.to_owned();
        self
    }

    /// Sets the evidence requirement.
    pub fn evidence(mut self, requirement: &str) -> Self {
        self.evidence_requirement = requirement.to_owned();
        self
    }

    /// Sets the plain-language title template.
    pub fn user_title(mut self, template: &str) -> Self {
        self.user_title = template.to_owned();
        self
    }

    /// Sets the plain-language explanation template.
    pub fn explain(mut self, template: &str) -> Self {
        self.explanation = template.to_owned();
        self
    }

    /// Sets the plain-language fix-step templates.
    pub fn fix(mut self, steps: &[&str]) -> Self {
        self.recommendations = steps.iter().map(|s| (*s).to_owned()).collect();
        self
    }

    /// Sets the default confidence (clamped to 0.0-1.0).
    pub fn confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    /// Sets the default classification.
    pub fn classification(mut self, classification: Classification) -> Self {
        self.classification = classification;
        self
    }

    /// Marks the rule as a context rule with the note added to the absorbing finding.
    pub fn context(mut self, note: &str) -> Self {
        self.role = RuleRole::Context;
        self.context_note = Some(note.to_owned());
        self
    }

    /// Marks the rule as a generic cause.
    pub fn generic_cause(mut self) -> Self {
        self.role = RuleRole::GenericCause;
        self
    }

    /// Sets recovery phrases (case-insensitive).
    pub fn recovers_on(mut self, markers: &[&str]) -> Self {
        self.recovery_markers = markers.iter().map(|m| m.to_ascii_lowercase()).collect();
        self
    }

    /// Do not attribute the finding to the plugin whose logger printed the line.
    pub fn ignore_logger_tag(mut self) -> Self {
        self.attribute_logger_tag = false;
        self
    }

    /// All user-facing templates of the rule.
    pub fn templates(&self) -> impl Iterator<Item = &str> {
        [self.user_title.as_str(), self.explanation.as_str()]
            .into_iter()
            .chain(self.recommendations.iter().map(String::as_str))
            .chain(self.context_note.as_deref())
    }

    /// Wraps the metadata in an [`Arc`] for sharing between hits.
    pub fn shared(self) -> Arc<Self> {
        Arc::new(self)
    }
}

/// Template variables of a hit (`plugin`, `port`, `missing_class`, ...).
pub type TemplateVars = BTreeMap<String, String>;

/// A single detection produced by a rule for one event (or one crash report).
///
/// Hits are aggregated into [`super::Finding`]s by the analysis stage; hits with the
/// same `rule.id` and `group_key` become one finding.
#[derive(Debug, Clone)]
pub struct Hit {
    /// The rule that fired.
    pub rule: Arc<RuleMeta>,
    /// Rule-specific grouping discriminator (e.g. stack signature, plugin name).
    pub group_key: String,
    /// Optional technical title suffix that identifies the subject.
    pub headline: Option<String>,
    /// Severity for this hit.
    pub severity: Severity,
    /// Confidence for this hit.
    pub confidence: f32,
    /// Classification for this hit.
    pub classification: Classification,
    /// Where/when.
    pub occurrence: Occurrence,
    /// Verbatim evidence.
    pub evidence: Vec<Evidence>,
    /// Explicit subject.
    pub subject: Subject,
    /// Implicated components.
    pub implicated: Vec<Implication>,
    /// Technical notes.
    pub notes: Vec<String>,
    /// Template variables for the user-facing texts.
    pub vars: TemplateVars,
    /// Context-note templates absorbed from context rules of the same log entry.
    pub context_notes: Vec<String>,
}

impl Hit {
    /// Creates a hit with the rule's default severity, confidence and classification.
    pub fn new(rule: Arc<RuleMeta>, group_key: String, occurrence: Occurrence) -> Self {
        Self {
            severity: rule.severity,
            confidence: rule.confidence,
            classification: rule.classification,
            rule,
            group_key,
            headline: None,
            occurrence,
            evidence: Vec::new(),
            subject: Subject::default(),
            implicated: Vec::new(),
            notes: Vec::new(),
            vars: TemplateVars::new(),
            context_notes: Vec::new(),
        }
    }

    /// Sets a template variable unless it is already set or `value` is empty.
    pub fn set_var_default(&mut self, name: &str, value: impl Into<String>) {
        let value = value.into();
        if !value.trim().is_empty() {
            self.vars.entry(name.to_owned()).or_insert(value);
        }
    }
}
