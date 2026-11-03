//! Memory exhaustion.

use anycasted_core::models::{Category, ExceptionChain, RuleMeta, Severity, ThrownException};

use crate::rule::{ExceptionRule, Extraction, LogRule, TextRule};

const OOM: &[&str] = &["java.lang.OutOfMemoryError"];

const RAISE_RAM: &str = "Check how much memory (RAM) the server is allowed to use (the -Xmx setting, or the memory slider in your hosting panel) and increase it if your plan allows.";
const REDUCE_LOAD: &str = "Lower view-distance and simulation-distance in server.properties, and limit large farms and dropped items, to reduce memory use.";
const FIND_LEAK: &str = "If memory use grows steadily until it crashes, something is leaking memory: install the spark plugin and run `/spark heapsummary` before it crashes to see what is using it.";
const SUSPECT: &str =
    "[[{suspect} appears in the error; check whether an update is available for it.]]";

/// Memory exhaustion is reported once per kind: the allocation site in the stack trace
/// is incidental (whichever thread allocated next), so stack signatures are not used.
fn single_group(_: &ExceptionChain, _: &ThrownException) -> Option<Extraction> {
    Some(Extraction {
        group: Some(String::new()),
        ..Extraction::default()
    })
}

fn oom_rule(meta: RuleMeta, messages: &[&str], priority: u8) -> ExceptionRule {
    let rule = ExceptionRule::new(meta.shared(), OOM)
        .priority(priority)
        .extract(single_group);
    if messages.is_empty() {
        rule
    } else {
        rule.message_any(messages)
    }
}

/// Exception rules for `OutOfMemoryError` variants.
pub fn exception_rules() -> Vec<ExceptionRule> {
    vec![
        oom_rule(
            RuleMeta::new("MEM-HEAP-EXHAUSTED", Category::Memory, Severity::Critical)
                .title("Java heap memory exhausted")
                .description("The JVM could not allocate an object because the heap is full. Afterwards the server is in an undefined state and usually crashes or stops responding.")
                .evidence("`java.lang.OutOfMemoryError: Java heap space`.")
                .user_title("The server ran out of memory")
                .explain("Java used up all the memory (RAM) the server is allowed to have. When this happens the server freezes or crashes and players are disconnected. Either the server needs more memory for what it's doing, or something (often a plugin, or too many loaded chunks and entities) is using far more than it should.")
                .fix(&[RAISE_RAM, REDUCE_LOAD, FIND_LEAK, SUSPECT]),
            &["java heap space"],
            30,
        ),
        oom_rule(
            RuleMeta::new("MEM-GC-OVERHEAD", Category::Memory, Severity::Critical)
                .title("GC overhead limit exceeded")
                .description("The JVM spent almost all of its time in garbage collection while recovering very little memory. The heap is effectively full.")
                .evidence("`java.lang.OutOfMemoryError: GC overhead limit exceeded`.")
                .user_title("The server is out of memory (spending all its time cleaning up)")
                .explain("Java spent almost all of its time trying to free memory and barely succeeded. The server is effectively out of memory, which causes heavy lag and usually a crash.")
                .fix(&[RAISE_RAM, REDUCE_LOAD, FIND_LEAK]),
            &["gc overhead limit exceeded"],
            30,
        ),
        oom_rule(
            RuleMeta::new("MEM-DIRECT-BUFFER", Category::Memory, Severity::Critical)
                .title("Direct buffer memory exhausted")
                .description("Off-heap (direct) buffer memory, used heavily by Netty for networking, is exhausted.")
                .evidence("`java.lang.OutOfMemoryError: Direct buffer memory`.")
                .user_title("The server ran out of network memory")
                .explain("Java ran out of the special memory it uses for network connections. This memory is separate from the normal memory limit, so the server can hit it even when RAM looks fine. Connections and chunk loading for players break when it happens.")
                .fix(&[
                    "Make sure your container or plan's memory limit is at least 1-2 GB higher than the -Xmx setting, so Java has room for this extra memory.",
                    "Restart the server. If it happens again, check for plugins that send a lot of data (maps, resource packs, holograms).",
                ]),
            &["direct buffer memory"],
            30,
        ),
        oom_rule(
            RuleMeta::new("MEM-METASPACE", Category::Memory, Severity::Critical)
                .title("Metaspace exhausted")
                .description("The JVM ran out of memory for class metadata, commonly from repeated plugin reloads leaking class loaders or a capped -XX:MaxMetaspaceSize.")
                .evidence("`java.lang.OutOfMemoryError: Metaspace`.")
                .user_title("The server ran out of memory for plugin code")
                .explain("Java ran out of the memory it uses to hold loaded plugin code. This almost always happens after plugins were reloaded several times (with /reload or a plugin manager) without a full restart.")
                .fix(&[
                    "Restart the server fully.",
                    "Stop using /reload and plugin managers that reload plugins; restart the server instead.",
                    "If a -XX:MaxMetaspaceSize flag is set in your startup command, remove it or raise it.",
                ]),
            &["metaspace", "compressed class space"],
            30,
        ),
        oom_rule(
            RuleMeta::new("MEM-NATIVE-THREAD", Category::Memory, Severity::Critical)
                .title("Unable to create native thread")
                .description("The JVM could not create a new thread, due to OS/container process limits or native memory exhaustion, often from a plugin creating threads without bound.")
                .evidence("`java.lang.OutOfMemoryError: unable to create native thread`.")
                .user_title("The server can't start any more threads")
                .explain("The server tried to start a new background thread and the system refused. Either the machine/container limits how many threads the server can have, or a plugin keeps creating threads and never stops them.")
                .fix(&[
                    "Restart the server to recover for now.",
                    "Ask your host whether your server has a process/thread limit and what it is.",
                    "Use spark (`/spark profiler`) to see thread counts; a plugin with hundreds of similar threads is the likely cause. Update or remove it.",
                ]),
            &["unable to create native thread", "unable to create new native thread"],
            30,
        ),
        oom_rule(
            RuleMeta::new("MEM-OUT-OF-MEMORY", Category::Memory, Severity::Critical)
                .title("OutOfMemoryError")
                .description("The JVM reported an out-of-memory condition not covered by a more specific rule.")
                .evidence("A `java.lang.OutOfMemoryError` in an exception chain.")
                .user_title("The server ran out of memory")
                .explain("Java reported that it ran out of memory[[ ({exception_message})]]. The server usually becomes unstable or crashes after this.")
                .fix(&[RAISE_RAM, FIND_LEAK]),
            &[],
            5,
        ),
    ]
}

/// Text rules for JVM-level memory failures.
pub fn log_rules() -> Vec<Box<dyn LogRule>> {
    vec![
        TextRule::new(
            RuleMeta::new("MEM-JVM-TERMINATED-OOM", Category::Memory, Severity::Critical)
                .title("JVM terminated due to OutOfMemoryError")
                .description("The JVM was configured to exit on OutOfMemoryError and terminated the server.")
                .evidence("A line containing `Terminating due to java.lang.OutOfMemoryError`.")
                .user_title("The server was shut down because it ran out of memory")
                .explain("The server ran out of memory, and Java is set up to stop the server immediately when that happens (so it can be restarted cleanly).")
                .fix(&[RAISE_RAM, REDUCE_LOAD, FIND_LEAK])
                .shared(),
            &["terminating due to java.lang.outofmemoryerror", "aborting due to java.lang.outofmemoryerror"],
        )
        .boxed(),
        TextRule::new(
            RuleMeta::new("MEM-NATIVE-ALLOCATION-FAILED", Category::Memory, Severity::Critical)
                .title("Native memory allocation failed")
                .description("The JVM could not obtain memory from the operating system; the host or container lacks memory for the configured heap plus JVM overhead.")
                .evidence("`There is insufficient memory for the Java Runtime Environment to continue` or `Native memory allocation (mmap|malloc) failed`.")
                .user_title("The machine doesn't have enough memory for the server")
                .explain("Java couldn't get memory from the operating system at all. The server is set to use more memory than the machine or container actually has available.")
                .fix(&[
                    "Lower -Xmx (or the memory setting in your panel) so it fits within your plan's memory with about 1-2 GB to spare.",
                    "Check whether other programs on the same machine are using memory.",
                    "Contact your host if your plan should have more memory than the server can get.",
                ])
                .shared(),
            &[
                "insufficient memory for the java runtime environment",
                "native memory allocation (mmap) failed",
                "native memory allocation (malloc) failed",
            ],
        )
        .boxed(),
    ]
}
