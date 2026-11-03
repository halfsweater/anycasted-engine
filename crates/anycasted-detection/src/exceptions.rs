//! Generic Java runtime exceptions.
//!
//! Most of these are [`RuleRole::GenericCause`](anycasted_core::models::RuleRole): when
//! the server printed them under a context message ("Could not pass event ... to Foo"),
//! they become a detail of that finding instead of a separate one.

use std::sync::Arc;

use anycasted_core::models::{Category, RuleMeta, Severity};

use crate::rule::ExceptionRule;

/// Rule id of the fallback for exceptions without a specific rule.
pub const UNCLASSIFIED_ID: &str = "JAVA-UNCLASSIFIED-EXCEPTION";

const UPDATE: &str = "Update {plugin|the plugin involved}[[ (the error came from code in {suspect})]] to the newest version that supports your server version.";
const REPORT: &str =
    "If it keeps happening, send the log lines shown below to the author of {plugin|that plugin}.";

/// Metadata for the fallback rule.
pub fn unclassified_meta() -> Arc<RuleMeta> {
    RuleMeta::new(UNCLASSIFIED_ID, Category::Exception, Severity::Error)
        .title("Unhandled Java exception")
        .description("A Java exception with a stack trace (or logged at WARN/ERROR level) that no specific rule recognizes. Reported so that no logged failure is silently dropped; its impact depends on where it was thrown.")
        .evidence("An exception header line (`fully.qualified.SomethingException: message`) with stack frames, or at WARN level or above.")
        .user_title("{plugin|The server} ran into an unexpected error[[ ({exception})]]")
        .explain("{plugin|Something on the server} hit an error: {error_hint|an unexpected error}. Whatever it was doing at that moment didn't finish.[[ The error came from code in {suspect}, so that plugin is the most likely source.]]")
        .fix(&[
            UPDATE,
            "Check how often this happens (shown below). A single occurrence is often harmless; a repeating one needs fixing.",
            REPORT,
        ])
        .generic_cause()
        .shared()
}

/// Built-in exception rules for common runtime exceptions.
pub fn exception_rules() -> Vec<ExceptionRule> {
    vec![
        ExceptionRule::new(
            RuleMeta::new("JAVA-NULL-POINTER", Category::Exception, Severity::Error)
                .title("NullPointerException")
                .description("Code dereferenced a null reference. A programming error in the component that threw it, often triggered by unexpected state, missing configuration values or an incompatible plugin/server version.")
                .evidence("A `java.lang.NullPointerException` in an exception chain.")
                .user_title("{plugin|A plugin} hit a missing-value error")
                .explain("{plugin|Some code on the server} expected a value that wasn't there[[ (`{null_ref}`)]], so it stopped what it was doing. Common causes are a missing or misspelled config setting, a required plugin that isn't installed, or a plugin that doesn't fully support your server version.[[ The error came from code in {suspect}.]]")
                .fix(&[
                    UPDATE,
                    "Check {plugin|the plugin}'s config files for missing or misspelled settings, then restart the server.",
                    "Make sure every plugin that {plugin|it} depends on is installed.",
                    REPORT,
                ])
                .generic_cause()
                .shared(),
            &["java.lang.NullPointerException"],
        ),
        ExceptionRule::new(
            RuleMeta::new("JAVA-ILLEGAL-STATE", Category::Exception, Severity::Error)
                .title("IllegalStateException")
                .description("An operation was attempted while the program was in a state that does not allow it.")
                .evidence("A `java.lang.IllegalStateException` in an exception chain.")
                .user_title("{plugin|A plugin} tried something at the wrong moment")
                .explain("{plugin|Some code on the server} tried to do something that wasn't allowed at that moment[[: {exception_message}]]. That action failed.[[ The error came from code in {suspect}.]]")
                .fix(&[UPDATE, REPORT])
                .generic_cause()
                .shared(),
            &["java.lang.IllegalStateException"],
        ),
        ExceptionRule::new(
            RuleMeta::new("JAVA-ILLEGAL-ARGUMENT", Category::Exception, Severity::Error)
                .title("IllegalArgumentException")
                .description("A method received an invalid argument; frequently an invalid configuration value (unknown material, sound, world) passed to the server API by a plugin.")
                .evidence("A `java.lang.IllegalArgumentException` in an exception chain.")
                .user_title("{plugin|A plugin} used an invalid value")
                .explain("{plugin|Some code on the server} was given a value it can't use[[: {exception_message}]]. This usually comes from a config setting naming something that doesn't exist in your Minecraft version, such as an item, sound, world or enchantment.")
                .fix(&[
                    "Look at the value mentioned in the error and search for it in {plugin|the plugin}'s config files.",
                    "Make sure item, sound, world and enchantment names are valid for your Minecraft version (names change between versions).",
                    UPDATE,
                ])
                .generic_cause()
                .shared(),
            &["java.lang.IllegalArgumentException"],
        ),
        ExceptionRule::new(
            RuleMeta::new("JAVA-CONCURRENT-MODIFICATION", Category::Exception, Severity::Error)
                .title("ConcurrentModificationException")
                .description("A collection was modified while being iterated, typically from another thread or inside an event handler. A thread-safety bug in the component that threw it.")
                .evidence("A `java.util.ConcurrentModificationException` in an exception chain.")
                .user_title("{plugin|A plugin} has a timing bug")
                .explain("Two parts of {plugin|a plugin}'s code changed the same data at the same time, so the operation failed. This is a bug in the plugin, not in your setup.[[ The error came from code in {suspect}.]]")
                .fix(&[UPDATE, REPORT])
                .generic_cause()
                .shared(),
            &["java.util.ConcurrentModificationException"],
        ),
        ExceptionRule::new(
            RuleMeta::new("JAVA-STACK-OVERFLOW", Category::Exception, Severity::Critical)
                .title("StackOverflowError")
                .description("A thread exhausted its call stack, almost always because of unbounded recursion. On the main server thread this usually crashes or freezes the server.")
                .evidence("A `java.lang.StackOverflowError` in an exception chain.")
                .user_title("{plugin|Something on the server} got stuck in an endless loop")
                .explain("{plugin|Some code} kept calling itself over and over until Java gave up. If this happens on the main server thread, the server freezes or crashes.[[ The error came from code in {suspect}.]]")
                .fix(&[
                    "[[Update {suspect}, or temporarily remove it to confirm it's the cause.]]",
                    "Look for two plugins reacting to each other's actions (for example both teleporting players or both changing the same event).",
                    REPORT,
                ])
                .shared(),
            &["java.lang.StackOverflowError"],
        ),
    ]
}
