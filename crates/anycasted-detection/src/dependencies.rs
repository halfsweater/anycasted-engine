//! Class-loading and linkage failures.

use anycasted_core::models::{
    Category, Classification, ExceptionChain, Implication, ImplicationBasis, RuleMeta, Severity,
    ThrownException,
};

use crate::attribution::plugin_for_class;
use crate::rule::{ExceptionRule, Extraction};

const MISSING_TITLE: &str = "{plugin|A plugin} can't find something it needs[[: {provider}]]";
const MISSING_EXPLAIN: &str = "{plugin|A plugin} tried to use code (`{missing_class|a Java class}`) that isn't available on the server.[[ That code normally comes from the {provider} plugin.]] This usually means a plugin it depends on is missing, failed to load, or is a version that doesn't match.";
const MISSING_FIX: &[&str] = &[
    "[[Install {provider} in your plugins folder (use the version {plugin|the plugin} asks for).]]",
    "Check {plugin|the plugin}'s download page for the plugins it requires, and install any that are missing.",
    "If those plugins are already installed, look in this report for an earlier error showing that one of them failed to load.",
    "Make sure {plugin|the plugin} and the plugins it needs are all built for your Minecraft version.",
];

const VERSION_TITLE: &str = "{plugin|A plugin} is built for a different version";
const VERSION_FIX: &[&str] = &[
    "Download the version of {plugin|the plugin} made for your exact Minecraft version.",
    "If {plugin|it} uses another plugin (an API or library), make sure both are versions that work together.",
    "Check that your server software itself is up to date.",
];

/// Extracts the missing class from `ClassNotFoundException`/`NoClassDefFoundError`.
fn missing_class(_: &ExceptionChain, exc: &ThrownException) -> Option<Extraction> {
    let raw = exc.message.as_deref()?.split_whitespace().next()?;
    let class = raw.replace('/', ".");
    let class = class.trim_end_matches(['.', ';']).to_owned();
    if class.is_empty() {
        return None;
    }
    let mut extraction = Extraction {
        headline: Some(class.clone()),
        detail: Some(class.clone()),
        group: Some(class.clone()),
        ..Extraction::default()
    }
    .var("missing_class", class.clone());
    if let Some(owner) = plugin_for_class(&class) {
        extraction.vars.push(("provider", owner.to_owned()));
        extraction.implicated.push(Implication {
            name: owner.to_owned(),
            basis: ImplicationBasis::ClassPackage,
            classification: Classification::Hypothesis,
            seen_loading: None,
        });
        extraction.notes.push(format!(
            "The missing class belongs to a package normally provided by {owner}."
        ));
    }
    Some(extraction)
}

/// Extracts the member signature from `NoSuchMethodError`/`NoSuchFieldError`.
fn missing_member(_: &ExceptionChain, exc: &ThrownException) -> Option<Extraction> {
    let member = exc.message.as_deref()?.trim().trim_matches('\'');
    (!member.is_empty()).then(|| {
        Extraction {
            detail: Some(member.to_owned()),
            group: Some(member.to_owned()),
            ..Extraction::default()
        }
        .var("member", member.to_owned())
    })
}

fn missing(id: &str, title: &str, description: &str, evidence: &str) -> RuleMeta {
    RuleMeta::new(id, Category::Dependency, Severity::Error)
        .title(title)
        .description(description)
        .evidence(evidence)
        .user_title(MISSING_TITLE)
        .explain(MISSING_EXPLAIN)
        .fix(MISSING_FIX)
}

fn version(id: &str, title: &str, description: &str, evidence: &str, explain: &str) -> RuleMeta {
    RuleMeta::new(id, Category::Dependency, Severity::Error)
        .title(title)
        .description(description)
        .evidence(evidence)
        .user_title(VERSION_TITLE)
        .explain(explain)
        .fix(VERSION_FIX)
}

/// Built-in dependency rules.
pub fn exception_rules() -> Vec<ExceptionRule> {
    vec![
        ExceptionRule::new(
            missing(
                "JAVA-CLASS-NOT-FOUND",
                "Class not found",
                "A class could not be found when loaded by name: a missing dependency (plugin or library), or an incompatible version that no longer contains the class.",
                "A `java.lang.ClassNotFoundException` in an exception chain.",
            )
            .shared(),
            &["java.lang.ClassNotFoundException"],
        )
        .extract(missing_class),
        ExceptionRule::new(
            missing(
                "JAVA-NO-CLASS-DEF-FOUND",
                "Class definition not found",
                "Code was compiled against a class that is not available at runtime: a required plugin/library is missing, failed to load earlier, or is an incompatible version.",
                "A `java.lang.NoClassDefFoundError` in an exception chain.",
            )
            .shared(),
            &["java.lang.NoClassDefFoundError"],
        )
        .extract(missing_class),
        ExceptionRule::new(
            version(
                "JAVA-NO-SUCH-METHOD",
                "Method not found (binary incompatibility)",
                "Code called a method that does not exist in the loaded version of a class; the caller was built against a different version of the server API or of another plugin.",
                "A `java.lang.NoSuchMethodError` in an exception chain.",
                "{plugin|A plugin} tried to use a feature that doesn't exist in the version of the server (or of another plugin) you're running. This happens when a plugin was made for a different Minecraft version or a different version of a plugin it relies on.[[ Missing feature: `{member}`.]]",
            )
            .shared(),
            &["java.lang.NoSuchMethodError"],
        )
        .extract(missing_member),
        ExceptionRule::new(
            version(
                "JAVA-NO-SUCH-FIELD",
                "Field not found (binary incompatibility)",
                "Code accessed a field that does not exist in the loaded version of a class; typical of plugins using server internals (NMS) built for another Minecraft version.",
                "A `java.lang.NoSuchFieldError` in an exception chain.",
                "{plugin|A plugin} relies on internal parts of the server that are different in your Minecraft version. Plugins that do this must be updated for every Minecraft release.[[ Missing part: `{member}`.]]",
            )
            .shared(),
            &["java.lang.NoSuchFieldError"],
        )
        .extract(missing_member),
        ExceptionRule::new(
            version(
                "JAVA-INCOMPATIBLE-CLASS-CHANGE",
                "Incompatible class change",
                "A class changed incompatibly between the version code was compiled against and the version loaded at runtime.",
                "A `java.lang.IncompatibleClassChangeError` or `java.lang.AbstractMethodError` in an exception chain.",
                "{plugin|A plugin} was built against a different version of the server or of another plugin, and the two no longer fit together.",
            )
            .shared(),
            &["java.lang.IncompatibleClassChangeError", "java.lang.AbstractMethodError"],
        )
        .extract(missing_member),
    ]
}
