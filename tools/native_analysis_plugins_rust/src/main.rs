// Copyright 2026 Fuzz Introspector Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Rust analysis plugin framework for fuzz-introspector.
//!
//! Reads a JSON request from stdin, dispatches to per-plugin handlers in
//! parallel (via rayon), and writes a JSON response to stdout.
//!
//! Protocol:
//!   Request  { schema_version: 1, plugins: [...], project_data: {...} }
//!   Response { schema_version: 1, status: "success"|"error", results: {...},
//!              reason_code?: "..." }

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::time::Instant;

// ── Function entry deserialization ────────────────────────────────────────────

/// Deserialised representation of one function from the project_data payload.
#[derive(Debug, Deserialize, Clone)]
struct FunctionEntry {
    #[serde(default)]
    name: String,
    #[serde(default)]
    hitcount: u64,
    #[serde(default)]
    arg_count: u64,
    #[serde(default)]
    cyclomatic_complexity: i64,
    #[serde(default)]
    total_cyclomatic_complexity: i64,
    #[serde(default)]
    new_unreached_complexity: i64,
    #[serde(default)]
    bb_count: u64,
    #[serde(default)]
    functions_reached: Vec<String>,
    /// Explicit count supplied by new Python payload (avoids sending the full
    /// list).  Zero means "not supplied" — callers must use
    /// `effective_reached_count()` instead of reading this field directly.
    #[serde(default)]
    functions_reached_count: usize,
    #[serde(default)]
    reached_by_fuzzers: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)] // deserialized from payload; available for future plugin use
    runtime_coverage_percent: f64,
    #[serde(default)]
    source_file: String,
    #[serde(default)]
    incoming_references: Vec<String>,
}

/// Parse `project_data["functions"]` into a `Vec<FunctionEntry>`.
/// Returns an empty vec if the key is absent or malformed.
fn parse_functions(project_data: &JsonValue) -> Vec<FunctionEntry> {
    project_data
        .get("functions")
        .and_then(|v| serde_json::from_value::<Vec<FunctionEntry>>(v.clone()).ok())
        .unwrap_or_default()
}

// ── Request / Response types ────────────────────────────────────────────────

/// Top-level request sent by the Python `NativePluginProxy`.
#[derive(Debug, Deserialize)]
struct Request {
    #[serde(default)]
    #[allow(dead_code)] // read by serde; re-echoed via schema_version local variable
    schema_version: i64,
    /// Names of plugins to run, e.g. ["optimal_targets", "calltree_analysis"].
    #[serde(default)]
    plugins: Vec<String>,
    /// Serialised project data passed to every plugin.
    #[serde(default)]
    project_data: JsonValue,
}

/// A single plugin's output: zero or more named tables plus a text summary.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PluginResult {
    /// Named data tables.  Keys are table identifiers; values are
    /// JSON arrays of row objects.  Empty when the stub is active.
    pub tables: HashMap<String, Vec<JsonValue>>,
    /// Human-readable summary string (may be empty).
    pub summary: String,
}

impl Default for PluginResult {
    fn default() -> Self {
        Self {
            tables: HashMap::new(),
            summary: String::new(),
        }
    }
}

/// Top-level response written to stdout.
#[derive(Debug, Serialize)]
struct Response {
    schema_version: i64,
    status: &'static str,
    /// Per-plugin results keyed by plugin name.
    results: HashMap<String, PluginResult>,
    /// Present only on error.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason_code: Option<String>,
    /// Wall-clock milliseconds for the full request.
    elapsed_ms: u64,
}

// ── Plugin implementations ───────────────────────────────────────────────────
//
// Each `run_*` function receives a reference to the project_data JSON value
// and returns a PluginResult.

/// Returns the effective number of functions reached by `f`.
///
/// New Python payloads send `functions_reached_count` (an integer) instead of
/// the full `functions_reached` list to save memory.  Old payloads still send
/// the list.  This helper bridges both formats:
///
/// * If `functions_reached_count > 0`, or `functions_reached` is empty while
///   `functions_reached_count == 0`, the explicit count is canonical.
/// * Otherwise (old payload: list is non-empty, count field absent/zero),
///   fall back to `functions_reached.len()`.
#[inline]
fn effective_reached_count(f: &FunctionEntry) -> usize {
    if f.functions_reached_count > 0 || f.functions_reached.is_empty() {
        f.functions_reached_count
    } else {
        f.functions_reached.len()
    }
}

/// Returns true when a function qualifies as an optimal fuzz target candidate.
///
/// Ports `qualifies_as_optimal_target()` from
/// `src/fuzz_introspector/analyses/optimal_targets.py` lines 196-227.
fn qualifies_as_optimal_target(f: &FunctionEntry) -> bool {
    if f.hitcount != 0 {
        return false;
    }
    if effective_reached_count(f) < 1 {
        return false;
    }
    if f.arg_count == 0 {
        return false;
    }
    if f.name.contains("main2") || f.name == "main" {
        return false;
    }
    if f.total_cyclomatic_complexity < 20 {
        return false;
    }
    if f.bb_count <= 1 {
        return false;
    }
    if f.new_unreached_complexity < 35 {
        return false;
    }
    true
}

/// `optimal_targets` analysis: rank unreached functions by unreached complexity.
///
/// Ports the core logic of `OptimalTargets.analysis_get_optimal_targets()` from
/// `src/fuzz_introspector/analyses/optimal_targets.py`.  Returns up to 200
/// candidate rows sorted descending by `new_unreached_complexity`.
fn run_optimal_targets(project_data: &JsonValue) -> PluginResult {
    log::debug!("[optimal_targets] running real implementation");

    let functions = parse_functions(project_data);

    // Filter in parallel, then collect and sort.
    let mut candidates: Vec<&FunctionEntry> = functions
        .par_iter()
        .filter(|f| qualifies_as_optimal_target(f))
        .collect();

    candidates.sort_unstable_by(|a, b| {
        b.new_unreached_complexity
            .cmp(&a.new_unreached_complexity)
    });
    candidates.truncate(200);

    let rows: Vec<JsonValue> = candidates
        .iter()
        .map(|f| {
            serde_json::json!({
                "function_name": f.name,
                "cyclomatic_complexity": f.cyclomatic_complexity,
                "total_cyclomatic_complexity": f.total_cyclomatic_complexity,
                "new_unreached_complexity": f.new_unreached_complexity,
                "functions_reached_count": effective_reached_count(f),
                "arg_count": f.arg_count,
                "bb_count": f.bb_count,
                "source_file": f.source_file,
            })
        })
        .collect();

    let summary = format!(
        "optimal_targets: {} candidate(s) found out of {} total functions",
        rows.len(),
        functions.len()
    );
    log::debug!("[optimal_targets] {}", summary);

    let mut tables = HashMap::new();
    tables.insert("optimal_targets".to_string(), rows);
    PluginResult { tables, summary }
}

/// `runtime_coverage_analysis`: find reached functions with remaining unreached complexity.
///
/// Finds functions where `hitcount > 0` (reached by at least one fuzzer) AND
/// `new_unreached_complexity > 20` (still has sub-complexity not yet exercised
/// at runtime).  Sorted descending by `new_unreached_complexity`, capped at 200.
///
/// This is the Rust equivalent of `RuntimeCoverageAnalysis.get_low_cov_high_line_funcs()`.
/// Because the payload does not include per-line coverage data, we use
/// `new_unreached_complexity > 20` as a proxy for "low coverage despite being reached".
fn run_runtime_coverage_analysis(project_data: &JsonValue) -> PluginResult {
    log::debug!("[runtime_coverage_analysis] running real implementation");

    let functions = parse_functions(project_data);

    let mut candidates: Vec<&FunctionEntry> = functions
        .par_iter()
        .filter(|f| f.hitcount > 0 && f.new_unreached_complexity > 20)
        .collect();

    candidates.sort_unstable_by(|a, b| {
        b.new_unreached_complexity
            .cmp(&a.new_unreached_complexity)
    });
    candidates.truncate(200);

    let rows: Vec<JsonValue> = candidates
        .iter()
        .map(|f| {
            serde_json::json!({
                "function_name": f.name,
                "hitcount": f.hitcount,
                "new_unreached_complexity": f.new_unreached_complexity,
                "total_cyclomatic_complexity": f.total_cyclomatic_complexity,
                "reached_by_fuzzers": f.reached_by_fuzzers,
            })
        })
        .collect();

    let summary = format!(
        "runtime_coverage_analysis: {} function(s) reached but with unreached sub-complexity",
        rows.len()
    );
    log::debug!("[runtime_coverage_analysis] {}", summary);

    let mut tables = HashMap::new();
    tables.insert("runtime_coverage".to_string(), rows);
    PluginResult { tables, summary }
}

/// `calltree_analysis`: emit a per-project reachability summary.
///
/// The Python `FuzzCalltreeAnalysis.analysis_func()` returns `""` (not
/// implemented).  The Rust version emits a single summary row describing
/// overall function reachability for the project.
fn run_calltree_analysis(project_data: &JsonValue) -> PluginResult {
    log::debug!("[calltree_analysis] running real implementation");

    let functions = parse_functions(project_data);
    let target_lang = project_data
        .get("target_lang")
        .and_then(JsonValue::as_str)
        .unwrap_or("unknown")
        .to_string();

    let total = functions.len() as u64;
    let reached = functions.par_iter().filter(|f| f.hitcount > 0).count() as u64;
    let unreached = total.saturating_sub(reached);
    let reach_pct = if total > 0 {
        (reached as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    // Round to one decimal place for readability.
    let reach_pct_rounded = (reach_pct * 10.0).round() / 10.0;

    let row = serde_json::json!({
        "total_functions": total,
        "reached_functions": reached,
        "unreached_functions": unreached,
        "reach_percentage": reach_pct_rounded,
        "target_lang": target_lang,
    });

    let summary = format!(
        "calltree_analysis: {reached}/{total} functions reached ({reach_pct_rounded:.1}%) \
         for lang={target_lang}"
    );
    log::debug!("[calltree_analysis] {}", summary);

    let mut tables = HashMap::new();
    tables.insert("calltree_nodes".to_string(), vec![row]);
    PluginResult { tables, summary }
}

// ── Sink coverage analysis ────────────────────────────────────────────────────

/// A single sink entry: CWE name, target language, package, function name.
struct SinkEntry {
    cwe: &'static str,
    lang: &'static str,
    package: &'static str,
    func: &'static str,
}

/// All known sink functions, embedded as static data.
/// Ported from `src/fuzz_introspector/analyses/data/cwe_data.py`.
static SINKS: &[SinkEntry] = &[
    // ── CWE78: Command Injection ─────────────────────────────────────────────
    SinkEntry { cwe: "CWE78", lang: "c-cpp", package: "", func: "system" },
    SinkEntry { cwe: "CWE78", lang: "c-cpp", package: "", func: "execl" },
    SinkEntry { cwe: "CWE78", lang: "c-cpp", package: "", func: "execlp" },
    SinkEntry { cwe: "CWE78", lang: "c-cpp", package: "", func: "execle" },
    SinkEntry { cwe: "CWE78", lang: "c-cpp", package: "", func: "execv" },
    SinkEntry { cwe: "CWE78", lang: "c-cpp", package: "", func: "execvp" },
    SinkEntry { cwe: "CWE78", lang: "c-cpp", package: "", func: "execve" },
    SinkEntry { cwe: "CWE78", lang: "c-cpp", package: "", func: "wordexp" },
    SinkEntry { cwe: "CWE78", lang: "c-cpp", package: "", func: "popen" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "<builtin>", func: "exec" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "<builtin>", func: "eval" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "subprocess", func: "call" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "subprocess", func: "run" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "subprocess", func: "Popen" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "subprocess", func: "check_output" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "os", func: "system" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "os", func: "popen" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "os", func: "spawn" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "os", func: "spawnl" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "os", func: "spawnle" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "os", func: "spawnlp" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "os", func: "spawnlpe" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "os", func: "spawnv" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "os", func: "spawnvp" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "os", func: "spawnve" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "os", func: "spawnvpe" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "os", func: "exec" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "os", func: "execl" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "os", func: "execle" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "os", func: "execlp" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "os", func: "execlpe" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "os", func: "execv" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "os", func: "execve" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "os", func: "execvp" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "asyncio", func: "create_subprocess_shell" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "asyncio", func: "create_subprocess_exec" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "code.InteractiveInterpreter", func: "runsource" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "code.InteractiveInterpreter", func: "runcode" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "code.InteractiveInterpreter", func: "write" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "code.InteractiveConsole", func: "push" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "code.InteractiveConsole", func: "interact" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "code.InteractiveConsole", func: "raw_input" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "code", func: "interact" },
    SinkEntry { cwe: "CWE78", lang: "python", package: "code", func: "compile_command" },
    SinkEntry { cwe: "CWE78", lang: "jvm", package: "java.lang.Runtime", func: "exec" },
    SinkEntry { cwe: "CWE78", lang: "jvm", package: "javax.xml.xpath.XPath", func: "compile" },
    SinkEntry { cwe: "CWE78", lang: "jvm", package: "javax.xml.xpath.XPath", func: "evaluate" },
    SinkEntry { cwe: "CWE78", lang: "jvm", package: "java.util.concurrent.Executor", func: "execute" },
    SinkEntry { cwe: "CWE78", lang: "jvm", package: "java.util.concurrent.Callable", func: "call" },
    SinkEntry { cwe: "CWE78", lang: "jvm", package: "java.lang.System", func: "console" },
    SinkEntry { cwe: "CWE78", lang: "jvm", package: "java.lang.System", func: "load" },
    SinkEntry { cwe: "CWE78", lang: "jvm", package: "java.lang.System", func: "loadLibrary" },
    SinkEntry { cwe: "CWE78", lang: "jvm", package: "java.lang.System", func: "mapLibraryName" },
    SinkEntry { cwe: "CWE78", lang: "jvm", package: "java.lang.System", func: "runFinalization" },
    SinkEntry { cwe: "CWE78", lang: "jvm", package: "java.lang.System", func: "exec" },
    SinkEntry { cwe: "CWE78", lang: "jvm", package: "java.lang.ProcessBuilder", func: "directory" },
    SinkEntry { cwe: "CWE78", lang: "jvm", package: "java.lang.ProcessBuilder", func: "inheritIO" },
    SinkEntry { cwe: "CWE78", lang: "jvm", package: "java.lang.ProcessBuilder", func: "command" },
    SinkEntry { cwe: "CWE78", lang: "jvm", package: "java.lang.ProcessBuilder", func: "redirectError" },
    SinkEntry { cwe: "CWE78", lang: "jvm", package: "java.lang.ProcessBuilder", func: "redirectErrorStream" },
    SinkEntry { cwe: "CWE78", lang: "jvm", package: "java.lang.ProcessBuilder", func: "redirectInput" },
    SinkEntry { cwe: "CWE78", lang: "jvm", package: "java.lang.ProcessBuilder", func: "redirectOutput" },
    SinkEntry { cwe: "CWE78", lang: "jvm", package: "java.lang.ProcessBuilder", func: "start" },
    // ── CWE79: Cross-site Scripting ──────────────────────────────────────────
    SinkEntry { cwe: "CWE79", lang: "c-cpp", package: "", func: "put" },
    SinkEntry { cwe: "CWE79", lang: "c-cpp", package: "", func: "puts" },
    SinkEntry { cwe: "CWE79", lang: "c-cpp", package: "", func: "getenv" },
    SinkEntry { cwe: "CWE79", lang: "c-cpp", package: "", func: "putc" },
    SinkEntry { cwe: "CWE79", lang: "c-cpp", package: "", func: "fputc" },
    SinkEntry { cwe: "CWE79", lang: "c-cpp", package: "", func: "putchar" },
    SinkEntry { cwe: "CWE79", lang: "python", package: "jinja2.Environment", func: "get_template" },
    SinkEntry { cwe: "CWE79", lang: "python", package: "jinja2.Environment", func: "from_string" },
    SinkEntry { cwe: "CWE79", lang: "python", package: "jinja2.Template", func: "render" },
    SinkEntry { cwe: "CWE79", lang: "python", package: "jinja2.Template", func: "stream" },
    SinkEntry { cwe: "CWE79", lang: "python", package: "flask", func: "make_response" },
    SinkEntry { cwe: "CWE79", lang: "jvm", package: "java.io.PrintWriter", func: "print" },
    SinkEntry { cwe: "CWE79", lang: "jvm", package: "java.io.PrintWriter", func: "printf" },
    SinkEntry { cwe: "CWE79", lang: "jvm", package: "java.io.PrintWriter", func: "println" },
    SinkEntry { cwe: "CWE79", lang: "jvm", package: "java.io.PrintWriter", func: "write" },
    SinkEntry { cwe: "CWE79", lang: "jvm", package: "java.io.OutputStream", func: "write" },
    // ── CWE787: Out-of-bounds Write ──────────────────────────────────────────
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "malloc" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "alligned_alloc" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "xmalloc" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "calloc" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "realloc" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "strcpy" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "strcpy_s" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "strncpy" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "strncpy_s" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "strcat" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "strcat_s" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "strncat" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "strncat_s" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "strxfrm" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "strdup" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "strndup" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "memchr" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "memset" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "memset_explicit" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "memset_s" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "memcpy" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "memcpy_s" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "memmove" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "memmove_s" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "memccpy" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "putc" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "fputc" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "putchar" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "puts" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "put" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "fwrite" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "ungetc" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "fputwc" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "putwc" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "fputws" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "putwchar" },
    SinkEntry { cwe: "CWE787", lang: "c-cpp", package: "", func: "ungetwc" },
    // ── CWE89: SQL Injection ─────────────────────────────────────────────────
    SinkEntry { cwe: "CWE89", lang: "c-cpp", package: "", func: "runSql" },
    SinkEntry { cwe: "CWE89", lang: "c-cpp", package: "", func: "runQuery" },
    SinkEntry { cwe: "CWE89", lang: "python", package: "cursor.MySQLCursor", func: "execute" },
    SinkEntry { cwe: "CWE89", lang: "python", package: "cursor.MySQLCursor", func: "executemany" },
    SinkEntry { cwe: "CWE89", lang: "python", package: "cursor.MySQLCursor", func: "executescript" },
    SinkEntry { cwe: "CWE89", lang: "python", package: "psycopg2.extensions.cursor", func: "execute" },
    SinkEntry { cwe: "CWE89", lang: "python", package: "psycopg2.extensions.cursor", func: "executemany" },
    SinkEntry { cwe: "CWE89", lang: "python", package: "psycopg2.extensions.cursor", func: "executescript" },
    SinkEntry { cwe: "CWE89", lang: "python", package: "sqlite3.Cursor", func: "execute" },
    SinkEntry { cwe: "CWE89", lang: "python", package: "sqlite3.Cursor", func: "executemany" },
    SinkEntry { cwe: "CWE89", lang: "python", package: "sqlite3.Cursor", func: "executescript" },
    SinkEntry { cwe: "CWE89", lang: "python", package: "sqlite3.dbapi2.Cursor", func: "execute" },
    SinkEntry { cwe: "CWE89", lang: "python", package: "sqlite3.dbapi2.Cursor", func: "executemany" },
    SinkEntry { cwe: "CWE89", lang: "python", package: "sqlite3.dbapi2.Cursor", func: "executescript" },
    SinkEntry { cwe: "CWE89", lang: "jvm", package: "java.sql.Statement", func: "execute" },
    SinkEntry { cwe: "CWE89", lang: "jvm", package: "java.sql.Statement", func: "executeBatch" },
    SinkEntry { cwe: "CWE89", lang: "jvm", package: "java.sql.Statement", func: "executeLargeBatch" },
    SinkEntry { cwe: "CWE89", lang: "jvm", package: "java.sql.Statement", func: "executeLargeUpdate" },
    SinkEntry { cwe: "CWE89", lang: "jvm", package: "java.sql.Statement", func: "executeQuery" },
    SinkEntry { cwe: "CWE89", lang: "jvm", package: "java.sql.Statement", func: "executeUpdate" },
    SinkEntry { cwe: "CWE89", lang: "jvm", package: "java.sql.Statement", func: "addBatch" },
    SinkEntry { cwe: "CWE89", lang: "jvm", package: "javax.persistence.EntityManager", func: "createNativeQuery" },
    SinkEntry { cwe: "CWE89", lang: "jvm", package: "javax.persistence.EntityManager", func: "createQuery" },
    SinkEntry { cwe: "CWE89", lang: "jvm", package: "javax.persistence.EntityManager", func: "createStoredProcedureQuery" },
    // ── CWE416: Use After Free ───────────────────────────────────────────────
    SinkEntry { cwe: "CWE416", lang: "c-cpp", package: "", func: "c_str" },
    SinkEntry { cwe: "CWE416", lang: "c-cpp", package: "", func: "getUniquePointer" },
    SinkEntry { cwe: "CWE416", lang: "c-cpp", package: "", func: "free" },
    SinkEntry { cwe: "CWE416", lang: "c-cpp", package: "", func: "get" },
    // ── CWE20: Improper Input Validation ─────────────────────────────────────
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "fread" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "fgetc" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "getc" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "fgets" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "getchar" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "gets" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "gets_s" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "get" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "fget" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "fgetwc" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "getwc" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "fgetws" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "getwchar" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "scanf" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "fscanf" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "sscanf" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "scanf_s" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "fscanf_s" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "sscanf_s" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "vscanf" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "vfscanf" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "vsscanf" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "vscanf_s" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "vfscanf_s" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "vsscanf_s" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "wscanf" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "fwscanf" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "swscanf" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "wscanf_s" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "fwscanf_s" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "swscanf_s" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "vwscanf" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "vfwscanf" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "vswscanf" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "vwscanf_s" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "vfwscanf_s" },
    SinkEntry { cwe: "CWE20", lang: "c-cpp", package: "", func: "vswscanf_s" },
    SinkEntry { cwe: "CWE20", lang: "python", package: "re", func: "compile" },
    SinkEntry { cwe: "CWE20", lang: "python", package: "re.Pattern", func: "match" },
    SinkEntry { cwe: "CWE20", lang: "python", package: "flask.Request", func: "get_data" },
    SinkEntry { cwe: "CWE20", lang: "python", package: "flask.Request", func: "get_json" },
    SinkEntry { cwe: "CWE20", lang: "python", package: "flask.Request", func: "args" },
    SinkEntry { cwe: "CWE20", lang: "python", package: "flask.Request", func: "charset" },
    SinkEntry { cwe: "CWE20", lang: "python", package: "flask.Request", func: "content_encoding" },
    SinkEntry { cwe: "CWE20", lang: "python", package: "flask.Request", func: "content_length" },
    SinkEntry { cwe: "CWE20", lang: "python", package: "flask.Request", func: "content_md5" },
    SinkEntry { cwe: "CWE20", lang: "python", package: "flask.Request", func: "content_type" },
    SinkEntry { cwe: "CWE20", lang: "python", package: "flask.Request", func: "cookies" },
    SinkEntry { cwe: "CWE20", lang: "python", package: "flask.Request", func: "files" },
    SinkEntry { cwe: "CWE20", lang: "python", package: "flask.Request", func: "headers" },
    SinkEntry { cwe: "CWE20", lang: "jvm", package: "javax.servlet.http.HttpServletRequest", func: "getAttribute" },
    SinkEntry { cwe: "CWE20", lang: "jvm", package: "javax.servlet.http.HttpServletRequest", func: "getAttributeNames" },
    SinkEntry { cwe: "CWE20", lang: "jvm", package: "javax.servlet.http.HttpServletRequest", func: "getAuthType" },
    SinkEntry { cwe: "CWE20", lang: "jvm", package: "javax.servlet.http.HttpServletRequest", func: "getCharacterEncoding" },
    SinkEntry { cwe: "CWE20", lang: "jvm", package: "javax.servlet.http.HttpServletRequest", func: "getContentType" },
    SinkEntry { cwe: "CWE20", lang: "jvm", package: "javax.servlet.http.HttpServletRequest", func: "getContextPath" },
    SinkEntry { cwe: "CWE20", lang: "jvm", package: "javax.servlet.http.HttpServletRequest", func: "getCookies" },
    SinkEntry { cwe: "CWE20", lang: "jvm", package: "javax.servlet.http.HttpServletRequest", func: "getDateHeader" },
    SinkEntry { cwe: "CWE20", lang: "jvm", package: "javax.servlet.http.HttpServletRequest", func: "getHeader" },
    SinkEntry { cwe: "CWE20", lang: "jvm", package: "javax.servlet.http.HttpServletRequest", func: "getHeaderNames" },
    SinkEntry { cwe: "CWE20", lang: "jvm", package: "javax.servlet.http.HttpServletRequest", func: "getIntHeader" },
    SinkEntry { cwe: "CWE20", lang: "jvm", package: "javax.servlet.http.HttpServletRequest", func: "getMethod" },
    SinkEntry { cwe: "CWE20", lang: "jvm", package: "javax.servlet.http.HttpServletRequest", func: "getParameter" },
    SinkEntry { cwe: "CWE20", lang: "jvm", package: "javax.servlet.http.HttpServletRequest", func: "getParameterMap" },
    SinkEntry { cwe: "CWE20", lang: "jvm", package: "javax.servlet.http.HttpServletRequest", func: "getParameterNames" },
    SinkEntry { cwe: "CWE20", lang: "jvm", package: "javax.servlet.http.HttpServletRequest", func: "getParameterValues" },
    SinkEntry { cwe: "CWE20", lang: "jvm", package: "javax.servlet.http.HttpServletRequest", func: "getPart" },
    SinkEntry { cwe: "CWE20", lang: "jvm", package: "javax.servlet.http.HttpServletRequest", func: "getParts" },
    SinkEntry { cwe: "CWE20", lang: "jvm", package: "javax.servlet.http.HttpServletRequest", func: "getPathInfo" },
    SinkEntry { cwe: "CWE20", lang: "jvm", package: "javax.servlet.http.HttpServletRequest", func: "getPathTranslated" },
    SinkEntry { cwe: "CWE20", lang: "jvm", package: "javax.servlet.http.HttpServletRequest", func: "getQueryString" },
    SinkEntry { cwe: "CWE20", lang: "jvm", package: "javax.servlet.http.HttpServletRequest", func: "getRemoteUser" },
    SinkEntry { cwe: "CWE20", lang: "jvm", package: "javax.servlet.http.HttpServletRequest", func: "getRequestedSessionId" },
    SinkEntry { cwe: "CWE20", lang: "jvm", package: "javax.servlet.http.HttpServletRequest", func: "getRequestURI" },
    SinkEntry { cwe: "CWE20", lang: "jvm", package: "javax.servlet.http.HttpServletRequest", func: "getRequestURL" },
    SinkEntry { cwe: "CWE20", lang: "jvm", package: "java.io.InputStream", func: "read" },
    SinkEntry { cwe: "CWE20", lang: "jvm", package: "java.io.BufferedReader", func: "read" },
    SinkEntry { cwe: "CWE20", lang: "jvm", package: "java.io.BufferedReader", func: "readLine" },
    SinkEntry { cwe: "CWE20", lang: "jvm", package: "java.lang.System", func: "getenv" },
    SinkEntry { cwe: "CWE20", lang: "jvm", package: "java.lang.System", func: "getProperties" },
    SinkEntry { cwe: "CWE20", lang: "jvm", package: "java.lang.System", func: "getProperty" },
    SinkEntry { cwe: "CWE20", lang: "jvm", package: "java.lang.System", func: "load" },
    SinkEntry { cwe: "CWE20", lang: "jvm", package: "java.lang.System", func: "loadLibrary" },
    SinkEntry { cwe: "CWE20", lang: "jvm", package: "java.lang.System", func: "getSecurityManager" },
    // ── CWE22: Path Traversal ────────────────────────────────────────────────
    SinkEntry { cwe: "CWE22", lang: "c-cpp", package: "", func: "open" },
    SinkEntry { cwe: "CWE22", lang: "c-cpp", package: "", func: "write" },
    SinkEntry { cwe: "CWE22", lang: "c-cpp", package: "", func: "ostrm" },
    SinkEntry { cwe: "CWE22", lang: "c-cpp", package: "", func: "copy" },
    SinkEntry { cwe: "CWE22", lang: "c-cpp", package: "", func: "copy_file" },
    SinkEntry { cwe: "CWE22", lang: "c-cpp", package: "", func: "copy_symlink" },
    SinkEntry { cwe: "CWE22", lang: "c-cpp", package: "", func: "absolute" },
    SinkEntry { cwe: "CWE22", lang: "c-cpp", package: "", func: "canonical" },
    SinkEntry { cwe: "CWE22", lang: "c-cpp", package: "", func: "relative" },
    SinkEntry { cwe: "CWE22", lang: "c-cpp", package: "", func: "create_directory" },
    SinkEntry { cwe: "CWE22", lang: "c-cpp", package: "", func: "create_directories" },
    SinkEntry { cwe: "CWE22", lang: "c-cpp", package: "", func: "creatE_hard_link" },
    SinkEntry { cwe: "CWE22", lang: "c-cpp", package: "", func: "create_symlink" },
    SinkEntry { cwe: "CWE22", lang: "c-cpp", package: "", func: "create_directory_symlink" },
    SinkEntry { cwe: "CWE22", lang: "c-cpp", package: "", func: "remove" },
    SinkEntry { cwe: "CWE22", lang: "c-cpp", package: "", func: "remove_all" },
    SinkEntry { cwe: "CWE22", lang: "c-cpp", package: "", func: "rename" },
    SinkEntry { cwe: "CWE22", lang: "c-cpp", package: "", func: "resize_file" },
    SinkEntry { cwe: "CWE22", lang: "c-cpp", package: "", func: "opendir" },
    SinkEntry { cwe: "CWE22", lang: "c-cpp", package: "", func: "readdir" },
    SinkEntry { cwe: "CWE22", lang: "c-cpp", package: "", func: "readdir_r" },
    SinkEntry { cwe: "CWE22", lang: "c-cpp", package: "", func: "fopen" },
    SinkEntry { cwe: "CWE22", lang: "python", package: "tarfile", func: "open" },
    SinkEntry { cwe: "CWE22", lang: "python", package: "zipfile", func: "open" },
    SinkEntry { cwe: "CWE22", lang: "python", package: "<builtin>", func: "open" },
    SinkEntry { cwe: "CWE22", lang: "python", package: "os.path", func: "join" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "java.io.InputStream", func: "<init>" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "java.io.File", func: "<init>" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "java.io.BufferedReader", func: "<init>" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "java.nio.file.Paths", func: "get" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "java.nio.file.Files", func: "createDirectories" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "java.nio.file.Files", func: "createDirectory" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "java.nio.file.Files", func: "createFile" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "java.nio.file.Files", func: "createLink" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "java.nio.file.Files", func: "createSymbolicLink" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "java.nio.file.Files", func: "createTempDirectory" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "java.nio.file.Files", func: "createTempFile" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "java.nio.file.Files", func: "delete" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "java.nio.file.Files", func: "deleteIfExists" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "java.nio.file.Files", func: "find" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "java.nio.file.Files", func: "move" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "java.nio.file.Files", func: "write" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "java.io.File", func: "createNewFile" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "java.io.File", func: "createTempFile" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "java.io.File", func: "delete" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "java.io.File", func: "deleteOnExit" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "java.io.File", func: "renameTo" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "org.apache.commons.io.FileUtils", func: "cleanDirectory" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "org.apache.commons.io.FileUtils", func: "copyDirectory" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "org.apache.commons.io.FileUtils", func: "copyFile" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "org.apache.commons.io.FileUtils", func: "copyFileToDirectory" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "org.apache.commons.io.FileUtils", func: "copyInputStreamToFile" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "org.apache.commons.io.FileUtils", func: "copyToDirectory" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "org.apache.commons.io.FileUtils", func: "copyToFile" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "org.apache.commons.io.FileUtils", func: "copyURLToFile" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "org.apache.commons.io.FileUtils", func: "createParentDirectories" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "org.apache.commons.io.FileUtils", func: "delete" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "org.apache.commons.io.FileUtils", func: "deleteDirectory" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "org.apache.commons.io.FileUtils", func: "deleteQuitely" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "org.apache.commons.io.FileUtils", func: "forceDelete" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "org.apache.commons.io.FileUtils", func: "forceDeleteOnExit" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "org.apache.commons.io.FileUtils", func: "forceMkdir" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "org.apache.commons.io.FileUtils", func: "forceMkdirParent" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "org.apache.commons.io.FileUtils", func: "moveDirectory" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "org.apache.commons.io.FileUtils", func: "moveDirectoryToDirectory" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "org.apache.commons.io.FileUtils", func: "moveFile" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "org.apache.commons.io.FileUtils", func: "moveFileToDirectory" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "org.apache.commons.io.FileUtils", func: "moveToDirectory" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "org.apache.commons.io.FileUtils", func: "newOutputStream" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "org.apache.commons.io.FileUtils", func: "openOutputStream" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "org.apache.commons.io.FileUtils", func: "write" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "org.apache.commons.io.FileUtils", func: "writeByteArrayToFile" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "org.apache.commons.io.FileUtils", func: "writeLines" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "org.apache.commons.io.FileUtils", func: "writeStringToFile" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "org.apache.commons.io.file.PathUtils", func: "cleanDirectory" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "org.apache.commons.io.file.PathUtils", func: "copyDirectory" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "org.apache.commons.io.file.PathUtils", func: "copyFile" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "org.apache.commons.io.file.PathUtils", func: "copyFileToDirectory" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "org.apache.commons.io.file.PathUtils", func: "delete" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "org.apache.commons.io.file.PathUtils", func: "deleteDirectory" },
    SinkEntry { cwe: "CWE22", lang: "jvm", package: "org.apache.commons.io.file.PathUtils", func: "deleteFile" },
    // ── CWE352: Cross-site Request Forgery ───────────────────────────────────
    SinkEntry { cwe: "CWE352", lang: "python", package: "django.middleware.csrf.CsrfViewMiddleware", func: "csrf_trusted_origins_hosts" },
    SinkEntry { cwe: "CWE352", lang: "python", package: "django.middleware.csrf.CsrfViewMiddleware", func: "allowed_origins_exact" },
    SinkEntry { cwe: "CWE352", lang: "python", package: "django.middleware.csrf.CsrfViewMiddleware", func: "allowed_origin_subdomains" },
    SinkEntry { cwe: "CWE352", lang: "python", package: "django.middleware.csrf.CsrfViewMiddleware", func: "_accept" },
    SinkEntry { cwe: "CWE352", lang: "python", package: "django.middleware.csrf.CsrfViewMiddleware", func: "_reject" },
    SinkEntry { cwe: "CWE352", lang: "python", package: "django.middleware.csrf.CsrfViewMiddleware", func: "_get_secret" },
    SinkEntry { cwe: "CWE352", lang: "python", package: "django.middleware.csrf.CsrfViewMiddleware", func: "_set_csrf_cookie" },
    SinkEntry { cwe: "CWE352", lang: "python", package: "django.middleware.csrf.CsrfViewMiddleware", func: "_origin_verified" },
    SinkEntry { cwe: "CWE352", lang: "python", package: "django.middleware.csrf.CsrfViewMiddleware", func: "_check_referer" },
    SinkEntry { cwe: "CWE352", lang: "python", package: "django.middleware.csrf.CsrfViewMiddleware", func: "_check_token" },
    SinkEntry { cwe: "CWE352", lang: "python", package: "django.middleware.csrf.CsrfViewMiddleware", func: "process_request" },
    SinkEntry { cwe: "CWE352", lang: "python", package: "django.middleware.csrf.CsrfViewMiddleware", func: "process_view" },
    SinkEntry { cwe: "CWE352", lang: "python", package: "django.middleware.csrf.CsrfViewMiddleware", func: "process_response" },
    SinkEntry { cwe: "CWE352", lang: "jvm", package: "org.springframework.security.config.annotation.web.builders.HttpSecurity", func: "csrf" },
    // ── CWE434: Unrestricted Upload of File ──────────────────────────────────
    SinkEntry { cwe: "CWE434", lang: "jvm", package: "javax.servlet.http.HttpServletRequest", func: "getContentType" },
    SinkEntry { cwe: "CWE434", lang: "jvm", package: "javax.servlet.http.HttpServletRequest", func: "getParameter" },
    SinkEntry { cwe: "CWE434", lang: "jvm", package: "javax.servlet.http.HttpServletRequest", func: "getParameterMap" },
    SinkEntry { cwe: "CWE434", lang: "jvm", package: "javax.servlet.http.HttpServletRequest", func: "getParameterNames" },
    SinkEntry { cwe: "CWE434", lang: "jvm", package: "javax.servlet.http.HttpServletRequest", func: "getParameterValues" },
    SinkEntry { cwe: "CWE434", lang: "jvm", package: "javax.servlet.http.HttpServletRequest", func: "getPart" },
    SinkEntry { cwe: "CWE434", lang: "jvm", package: "javax.servlet.http.HttpServletRequest", func: "getParts" },
    SinkEntry { cwe: "CWE434", lang: "jvm", package: "java.io.InputStream", func: "read" },
    SinkEntry { cwe: "CWE434", lang: "jvm", package: "java.io.BufferedReader", func: "read" },
    SinkEntry { cwe: "CWE434", lang: "jvm", package: "java.io.BufferedReader", func: "readLine" },
    SinkEntry { cwe: "CWE434", lang: "jvm", package: "java.io.BufferedWriter", func: "write" },
    SinkEntry { cwe: "CWE434", lang: "jvm", package: "java.io.OutputStream", func: "write" },
    SinkEntry { cwe: "CWE434", lang: "jvm", package: "java.lang.System", func: "getenv" },
    SinkEntry { cwe: "CWE434", lang: "jvm", package: "java.lang.System", func: "getProperties" },
    SinkEntry { cwe: "CWE434", lang: "jvm", package: "java.lang.System", func: "getProperty" },
    SinkEntry { cwe: "CWE434", lang: "jvm", package: "java.lang.System", func: "load" },
    SinkEntry { cwe: "CWE434", lang: "jvm", package: "java.lang.System", func: "loadLibrary" },
    SinkEntry { cwe: "CWE434", lang: "jvm", package: "java.lang.System", func: "getSecurityManager" },
];

/// Check whether a function name matches a sink entry for the given language.
///
/// Matching logic mirrors `_filter_function_list` in `sinks_analyser.py`:
/// - `c-cpp`: demangle by stripping everything up to the last `::`, then match
///   on bare function name (package always empty).
/// - `python`: function name may be `<package>.<func>` or just `<func>`;
///   source_file is the package for non-`<builtin>` functions.
/// - `jvm`: function name is `[package].method(sig...)`; strip brackets and
///   signature, then split on last `.`.
fn matches_sink(f: &FunctionEntry, sink: &SinkEntry, lang: &str) -> bool {
    if sink.lang != lang {
        return false;
    }
    match lang {
        "c-cpp" => {
            // Demangle: take the segment after the last `::`
            let bare = if let Some(pos) = f.name.rfind("::") {
                &f.name[pos + 2..]
            } else {
                &f.name
            };
            sink.package.is_empty() && bare == sink.func
        }
        "python" => {
            let func_name = &f.name;
            let package = &f.source_file;
            // Handle `<builtin>.func` style names
            if func_name.starts_with("<builtin>.") {
                let bare = &func_name[10..];
                return sink.package == "<builtin>" && bare == sink.func;
            }
            sink.package == package.as_str() && func_name == sink.func
        }
        "jvm" => {
            // Strip leading `[` and trailing `]`
            let name = f.name.trim_start_matches('[');
            let name = if let Some(pos) = name.find(']') { &name[..pos] } else { name };
            // Strip signature: everything from `(` onward
            let name = if let Some(pos) = name.find('(') { &name[..pos] } else { name };
            if let Some(dot) = name.rfind('.') {
                let pkg = &name[..dot];
                let meth = &name[dot + 1..];
                sink.package == pkg && sink.func == meth
            } else {
                false
            }
        }
        _ => false,
    }
}

/// `sink_coverage_analysis`: find sink functions present in the project and
/// report which callers reach them (via `incoming_references`).
///
/// Ports the core identification logic of `SinkCoverageAnalyser` from
/// `src/fuzz_introspector/analyses/sinks_analyser.py`.
/// Returns one row per matched sink.  Each row contains:
///   - `func_name`: the matched function name
///   - `cwe`: the CWE identifier
///   - `source_file`: source location
///   - `reached_by_fuzzers`: list of fuzzers that statically reach this sink
///   - `callers`: list of `incoming_references` entries for this function
fn run_sink_coverage_analysis(project_data: &JsonValue) -> PluginResult {
    log::debug!("[sink_coverage_analysis] running");

    let functions = parse_functions(project_data);
    let target_lang = project_data
        .get("target_lang")
        .and_then(JsonValue::as_str)
        .unwrap_or("c-cpp");

    // Build a lookup from function name → FunctionEntry for caller discovery.
    let name_to_func: HashMap<&str, &FunctionEntry> =
        functions.iter().map(|f| (f.name.as_str(), f)).collect();

    let rows: Vec<JsonValue> = functions
        .par_iter()
        .filter_map(|f| {
            // Find the first matching sink entry for this function.
            let sink = SINKS.iter().find(|s| matches_sink(f, s, target_lang))?;

            // Collect unique caller names from incoming_references.
            let mut callers: Vec<&str> = f.incoming_references.iter().map(|s| s.as_str()).collect();
            callers.sort_unstable();
            callers.dedup();

            // Determine which callers are themselves reached by fuzzers.
            let fuzzer_callers: Vec<&str> = callers
                .iter()
                .copied()
                .filter(|caller| {
                    name_to_func
                        .get(caller)
                        .map(|cf| !cf.reached_by_fuzzers.is_empty())
                        .unwrap_or(false)
                })
                .collect();

            Some(serde_json::json!({
                "func_name": f.name,
                "cwe": sink.cwe,
                "source_file": f.source_file,
                "reached_by_fuzzers": f.reached_by_fuzzers,
                "callers": callers,
                "fuzzer_callers": fuzzer_callers,
            }))
        })
        .collect();

    // Collect unique CWEs seen across matched sinks.
    let mut cwes_seen: Vec<&str> = rows
        .iter()
        .filter_map(|r| r.get("cwe").and_then(|v| v.as_str()))
        .collect();
    cwes_seen.sort_unstable();
    cwes_seen.dedup();

    let summary = format!(
        "sink_coverage_analysis: {} sink(s) found across {} CWE(s)",
        rows.len(),
        cwes_seen.len()
    );
    log::debug!("[sink_coverage_analysis] {}", summary);

    let mut tables = HashMap::new();
    tables.insert("sink_coverage".to_string(), rows);
    PluginResult { tables, summary }
}

/// Dispatcher: route a plugin name to its handler function.
///
/// Returns `None` for unknown plugin names so the caller can log and skip.
fn dispatch_plugin(name: &str, project_data: &JsonValue) -> Option<PluginResult> {
    match name {
        "optimal_targets" => Some(run_optimal_targets(project_data)),
        "runtime_coverage_analysis" => Some(run_runtime_coverage_analysis(project_data)),
        "calltree_analysis" => Some(run_calltree_analysis(project_data)),
        "sink_coverage_analysis" => Some(run_sink_coverage_analysis(project_data)),
        _ => {
            log::warn!("unknown plugin requested: {:?}", name);
            None
        }
    }
}

// ── Request execution ────────────────────────────────────────────────────────

/// Run all requested plugins, using rayon for parallel dispatch.
///
/// Plugin names that are not recognised are silently omitted from `results`.
fn run_request(request: &Request) -> HashMap<String, PluginResult> {
    // Collect (name, result) pairs in parallel; rayon preserves input order.
    request
        .plugins
        .par_iter()
        .filter_map(|plugin_name| {
            dispatch_plugin(plugin_name, &request.project_data)
                .map(|result| (plugin_name.clone(), result))
        })
        .collect()
}

// ── I/O helpers ──────────────────────────────────────────────────────────────

fn emit_response(response: &Response) {
    let mut stdout = io::stdout().lock();
    if serde_json::to_writer(&mut stdout, response).is_ok() {
        let _ = stdout.write_all(b"\n");
    }
}

fn build_ok_response(
    schema_version: i64,
    results: HashMap<String, PluginResult>,
    elapsed_ms: u64,
) -> Response {
    Response {
        schema_version,
        status: "success",
        results,
        reason_code: None,
        elapsed_ms,
    }
}

fn build_error_response(schema_version: i64, reason_code: &str, elapsed_ms: u64) -> Response {
    Response {
        schema_version,
        status: "error",
        results: HashMap::new(),
        reason_code: Some(reason_code.to_string()),
        elapsed_ms,
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    env_logger::init();

    let started = Instant::now();
    let mut raw_payload = String::new();

    if let Err(err) = io::stdin().read_to_string(&mut raw_payload) {
        let elapsed_ms = started.elapsed().as_millis() as u64;
        emit_response(&build_error_response(0, "io_error", elapsed_ms));
        eprintln!("failed reading stdin: {err}");
        return;
    }

    // Peek at schema_version before full deserialisation so we can echo it back
    // in error responses even if the payload is otherwise malformed.
    let schema_version: i64 = serde_json::from_str::<JsonValue>(&raw_payload)
        .ok()
        .and_then(|v| v.get("schema_version").and_then(JsonValue::as_i64))
        .unwrap_or(0);

    let request = match serde_json::from_str::<Request>(&raw_payload) {
        Ok(r) => r,
        Err(err) => {
            let elapsed_ms = started.elapsed().as_millis() as u64;
            emit_response(&build_error_response(
                schema_version,
                "invalid_request",
                elapsed_ms,
            ));
            eprintln!("invalid request payload: {err}");
            return;
        }
    };

    log::info!(
        "processing {} plugin(s): {:?}",
        request.plugins.len(),
        request.plugins
    );

    let results = run_request(&request);
    let elapsed_ms = started.elapsed().as_millis() as u64;

    log::info!(
        "completed {} plugin(s) in {}ms",
        results.len(),
        elapsed_ms
    );

    emit_response(&build_ok_response(schema_version, results, elapsed_ms));
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_request(plugins: &[&str]) -> Request {
        Request {
            schema_version: 1,
            plugins: plugins.iter().map(|s| s.to_string()).collect(),
            project_data: json!({}),
        }
    }

    /// Minimal project_data payload with three functions used across plugin tests.
    fn sample_project_data() -> JsonValue {
        json!({
            "function_count": 3,
            "fuzzer_count": 1,
            "target_lang": "c-cpp",
            "has_coverage_data": false,
            "functions": [
                {
                    "name": "foo",
                    "hitcount": 0,
                    "arg_count": 2,
                    "cyclomatic_complexity": 25,
                    "total_cyclomatic_complexity": 80,
                    "new_unreached_complexity": 60,
                    "bb_count": 5,
                    "functions_reached": ["bar", "baz"],
                    "reached_by_fuzzers": [],
                    "runtime_coverage_percent": 0.0,
                    "source_file": "foo.cpp"
                },
                {
                    "name": "bar",
                    "hitcount": 1,
                    "arg_count": 1,
                    "cyclomatic_complexity": 10,
                    "total_cyclomatic_complexity": 30,
                    "new_unreached_complexity": 25,
                    "bb_count": 3,
                    "functions_reached": [],
                    "reached_by_fuzzers": ["fuzzer1"],
                    "runtime_coverage_percent": 40.0,
                    "source_file": "bar.cpp"
                },
                {
                    "name": "main",
                    "hitcount": 0,
                    "arg_count": 0,
                    "cyclomatic_complexity": 1,
                    "total_cyclomatic_complexity": 1,
                    "new_unreached_complexity": 0,
                    "bb_count": 1,
                    "functions_reached": [],
                    "reached_by_fuzzers": [],
                    "runtime_coverage_percent": 0.0,
                    "source_file": "main.cpp"
                }
            ]
        })
    }

    // ── dispatch tests ───────────────────────────────────────────────────────

    #[test]
    fn dispatch_optimal_targets_returns_some() {
        let result = dispatch_plugin("optimal_targets", &json!({}));
        assert!(result.is_some());
    }

    #[test]
    fn dispatch_runtime_coverage_analysis_returns_some() {
        let result = dispatch_plugin("runtime_coverage_analysis", &json!({}));
        assert!(result.is_some());
    }

    #[test]
    fn dispatch_calltree_analysis_returns_some() {
        let result = dispatch_plugin("calltree_analysis", &json!({}));
        assert!(result.is_some());
    }

    #[test]
    fn dispatch_unknown_plugin_returns_none() {
        let result = dispatch_plugin("no_such_plugin", &json!({}));
        assert!(result.is_none());
    }

    // ── optimal_targets tests ────────────────────────────────────────────────

    #[test]
    fn optimal_targets_has_expected_table_key() {
        let result = run_optimal_targets(&json!({}));
        assert!(result.tables.contains_key("optimal_targets"));
        assert!(!result.summary.is_empty());
    }

    #[test]
    fn optimal_targets_empty_functions_returns_empty_table() {
        let result = run_optimal_targets(&json!({"functions": []}));
        assert!(result.tables["optimal_targets"].is_empty());
    }

    #[test]
    fn optimal_targets_selects_foo_not_main_or_bar() {
        let data = sample_project_data();
        let result = run_optimal_targets(&data);
        let rows = &result.tables["optimal_targets"];
        // foo qualifies: hitcount=0, arg_count=2, tcc=80>=20, bb=5>1, nuc=60>=35,
        //                functions_reached=["bar","baz"] len>=1, name not "main"/"main2"
        assert_eq!(rows.len(), 1, "expected exactly foo; got {:?}", rows);
        assert_eq!(rows[0]["function_name"], "foo");
    }

    #[test]
    fn optimal_targets_excludes_main() {
        let data = json!({
            "functions": [{
                "name": "main",
                "hitcount": 0,
                "arg_count": 2,
                "cyclomatic_complexity": 30,
                "total_cyclomatic_complexity": 80,
                "new_unreached_complexity": 60,
                "bb_count": 5,
                "functions_reached": ["bar"],
                "reached_by_fuzzers": [],
                "runtime_coverage_percent": 0.0,
                "source_file": "main.cpp"
            }]
        });
        let result = run_optimal_targets(&data);
        assert!(result.tables["optimal_targets"].is_empty(), "main must be excluded");
    }

    #[test]
    fn optimal_targets_excludes_main2_substring() {
        let data = json!({
            "functions": [{
                "name": "setup_main2_handler",
                "hitcount": 0,
                "arg_count": 2,
                "cyclomatic_complexity": 30,
                "total_cyclomatic_complexity": 80,
                "new_unreached_complexity": 60,
                "bb_count": 5,
                "functions_reached": ["bar"],
                "reached_by_fuzzers": [],
                "runtime_coverage_percent": 0.0,
                "source_file": "x.cpp"
            }]
        });
        let result = run_optimal_targets(&data);
        assert!(result.tables["optimal_targets"].is_empty(), "main2 substring must be excluded");
    }

    #[test]
    fn optimal_targets_excludes_already_reached() {
        let data = json!({
            "functions": [{
                "name": "foo",
                "hitcount": 1,
                "arg_count": 2,
                "cyclomatic_complexity": 30,
                "total_cyclomatic_complexity": 80,
                "new_unreached_complexity": 60,
                "bb_count": 5,
                "functions_reached": ["bar"],
                "reached_by_fuzzers": ["fuzzer1"],
                "runtime_coverage_percent": 0.0,
                "source_file": "foo.cpp"
            }]
        });
        let result = run_optimal_targets(&data);
        assert!(result.tables["optimal_targets"].is_empty(), "hitcount>0 must be excluded");
    }

    #[test]
    fn optimal_targets_sorted_descending_by_new_unreached_complexity() {
        let data = json!({
            "functions": [
                {
                    "name": "alpha",
                    "hitcount": 0, "arg_count": 2, "cyclomatic_complexity": 30,
                    "total_cyclomatic_complexity": 80, "new_unreached_complexity": 40,
                    "bb_count": 5, "functions_reached": ["x"], "reached_by_fuzzers": [],
                    "runtime_coverage_percent": 0.0, "source_file": "a.cpp"
                },
                {
                    "name": "beta",
                    "hitcount": 0, "arg_count": 2, "cyclomatic_complexity": 30,
                    "total_cyclomatic_complexity": 80, "new_unreached_complexity": 80,
                    "bb_count": 5, "functions_reached": ["y"], "reached_by_fuzzers": [],
                    "runtime_coverage_percent": 0.0, "source_file": "b.cpp"
                }
            ]
        });
        let result = run_optimal_targets(&data);
        let rows = &result.tables["optimal_targets"];
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["function_name"], "beta", "beta has higher nuc");
        assert_eq!(rows[1]["function_name"], "alpha");
    }

    // ── runtime_coverage_analysis tests ─────────────────────────────────────

    #[test]
    fn runtime_coverage_has_expected_table_key() {
        let result = run_runtime_coverage_analysis(&json!({}));
        assert!(result.tables.contains_key("runtime_coverage"));
        assert!(!result.summary.is_empty());
    }

    #[test]
    fn runtime_coverage_empty_functions_returns_empty_table() {
        let result = run_runtime_coverage_analysis(&json!({"functions": []}));
        assert!(result.tables["runtime_coverage"].is_empty());
    }

    #[test]
    fn runtime_coverage_selects_bar_not_foo_or_main() {
        let data = sample_project_data();
        let result = run_runtime_coverage_analysis(&data);
        let rows = &result.tables["runtime_coverage"];
        // bar: hitcount=1 >0 AND new_unreached_complexity=25 >20  → included
        // foo: hitcount=0  → excluded
        // main: hitcount=0 → excluded
        assert_eq!(rows.len(), 1, "expected only bar; got {:?}", rows);
        assert_eq!(rows[0]["function_name"], "bar");
    }

    #[test]
    fn runtime_coverage_excludes_unreached_functions() {
        let data = json!({
            "functions": [{
                "name": "unreached",
                "hitcount": 0, "arg_count": 2, "cyclomatic_complexity": 30,
                "total_cyclomatic_complexity": 80, "new_unreached_complexity": 60,
                "bb_count": 5, "functions_reached": ["x"], "reached_by_fuzzers": [],
                "runtime_coverage_percent": 0.0, "source_file": "u.cpp"
            }]
        });
        let result = run_runtime_coverage_analysis(&data);
        assert!(result.tables["runtime_coverage"].is_empty(), "hitcount=0 must be excluded");
    }

    #[test]
    fn runtime_coverage_excludes_low_unreached_complexity() {
        let data = json!({
            "functions": [{
                "name": "reached_but_simple",
                "hitcount": 5, "arg_count": 2, "cyclomatic_complexity": 5,
                "total_cyclomatic_complexity": 10, "new_unreached_complexity": 10,
                "bb_count": 2, "functions_reached": [], "reached_by_fuzzers": ["fuzzer1"],
                "runtime_coverage_percent": 90.0, "source_file": "s.cpp"
            }]
        });
        let result = run_runtime_coverage_analysis(&data);
        assert!(
            result.tables["runtime_coverage"].is_empty(),
            "nuc<=20 must be excluded"
        );
    }

    // ── calltree_analysis tests ───────────────────────────────────────────────

    #[test]
    fn calltree_analysis_has_expected_table_key() {
        let result = run_calltree_analysis(&json!({}));
        assert!(result.tables.contains_key("calltree_nodes"));
        assert!(!result.summary.is_empty());
    }

    #[test]
    fn calltree_analysis_empty_project_returns_one_summary_row() {
        let data = json!({"functions": [], "target_lang": "c-cpp"});
        let result = run_calltree_analysis(&data);
        let rows = &result.tables["calltree_nodes"];
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["total_functions"], 0);
        assert_eq!(rows[0]["reached_functions"], 0);
        assert_eq!(rows[0]["reach_percentage"], 0.0);
        assert_eq!(rows[0]["target_lang"], "c-cpp");
    }

    #[test]
    fn calltree_analysis_counts_reached_functions() {
        let data = sample_project_data();
        let result = run_calltree_analysis(&data);
        let rows = &result.tables["calltree_nodes"];
        assert_eq!(rows.len(), 1);
        // bar has hitcount=1; foo and main have hitcount=0
        assert_eq!(rows[0]["total_functions"], 3);
        assert_eq!(rows[0]["reached_functions"], 1);
        assert_eq!(rows[0]["unreached_functions"], 2);
        assert_eq!(rows[0]["target_lang"], "c-cpp");
    }

    #[test]
    fn calltree_analysis_reach_percentage_zero_for_no_functions() {
        let data = json!({"target_lang": "rust"});
        let result = run_calltree_analysis(&data);
        let rows = &result.tables["calltree_nodes"];
        assert_eq!(rows[0]["reach_percentage"], 0.0);
    }

    // ── parallel dispatch tests ──────────────────────────────────────────────

    #[test]
    fn run_request_all_known_plugins() {
        let request = make_request(&[
            "optimal_targets",
            "runtime_coverage_analysis",
            "calltree_analysis",
        ]);
        let results = run_request(&request);
        assert_eq!(results.len(), 3);
        assert!(results.contains_key("optimal_targets"));
        assert!(results.contains_key("runtime_coverage_analysis"));
        assert!(results.contains_key("calltree_analysis"));
    }

    #[test]
    fn run_request_unknown_plugins_are_omitted() {
        let request = make_request(&["optimal_targets", "no_such_plugin"]);
        let results = run_request(&request);
        assert_eq!(results.len(), 1);
        assert!(results.contains_key("optimal_targets"));
        assert!(!results.contains_key("no_such_plugin"));
    }

    #[test]
    fn run_request_empty_plugins_list_returns_empty_results() {
        let request = make_request(&[]);
        let results = run_request(&request);
        assert!(results.is_empty());
    }

    // ── serialisation round-trip test ────────────────────────────────────────

    #[test]
    fn plugin_result_round_trips_through_json() {
        let original = PluginResult {
            tables: {
                let mut t = HashMap::new();
                t.insert("test_table".to_string(), vec![json!({"key": "value"})]);
                t
            },
            summary: "test summary".to_string(),
        };

        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: PluginResult = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.summary, original.summary);
        assert!(deserialized.tables.contains_key("test_table"));
    }

    // ── response structure tests ─────────────────────────────────────────────

    #[test]
    fn ok_response_has_success_status() {
        let response = build_ok_response(1, HashMap::new(), 42);
        assert_eq!(response.status, "success");
        assert_eq!(response.schema_version, 1);
        assert_eq!(response.elapsed_ms, 42);
        assert!(response.reason_code.is_none());
    }

    #[test]
    fn error_response_has_error_status_and_reason_code() {
        let response = build_error_response(1, "test_error", 10);
        assert_eq!(response.status, "error");
        assert_eq!(response.reason_code.as_deref(), Some("test_error"));
        assert!(response.results.is_empty());
    }

    // ── FunctionEntry deserialization tests ──────────────────────────────────

    #[test]
    fn parse_functions_returns_empty_for_missing_key() {
        let data = json!({"function_count": 5});
        assert!(parse_functions(&data).is_empty());
    }

    #[test]
    fn parse_functions_handles_defaults_for_missing_fields() {
        let data = json!({"functions": [{"name": "minimal"}]});
        let funcs = parse_functions(&data);
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0].name, "minimal");
        assert_eq!(funcs[0].hitcount, 0);
        assert_eq!(funcs[0].arg_count, 0);
    }

    // ── effective_reached_count / functions_reached_count tests ──────────────

    /// New payload: integer count only, no list.  effective_reached_count
    /// should return the integer directly.
    #[test]
    fn effective_reached_count_uses_count_field_when_list_absent() {
        let data = json!({"functions": [{
            "name": "f",
            "hitcount": 0, "arg_count": 2, "cyclomatic_complexity": 30,
            "total_cyclomatic_complexity": 80, "new_unreached_complexity": 50,
            "bb_count": 4, "functions_reached_count": 7,
            "reached_by_fuzzers": [],
            "runtime_coverage_percent": 0.0, "source_file": "f.cpp"
        }]});
        let funcs = parse_functions(&data);
        assert_eq!(effective_reached_count(&funcs[0]), 7);
    }

    /// Old payload: list only, no count field.  effective_reached_count should
    /// fall back to list length.
    #[test]
    fn effective_reached_count_falls_back_to_list_len() {
        let data = json!({"functions": [{
            "name": "f",
            "hitcount": 0, "arg_count": 2, "cyclomatic_complexity": 30,
            "total_cyclomatic_complexity": 80, "new_unreached_complexity": 50,
            "bb_count": 4, "functions_reached": ["a", "b", "c"],
            "reached_by_fuzzers": [],
            "runtime_coverage_percent": 0.0, "source_file": "f.cpp"
        }]});
        let funcs = parse_functions(&data);
        assert_eq!(effective_reached_count(&funcs[0]), 3);
    }

    /// Both absent → zero (genuinely empty).
    #[test]
    fn effective_reached_count_zero_when_both_absent() {
        let data = json!({"functions": [{"name": "f"}]});
        let funcs = parse_functions(&data);
        assert_eq!(effective_reached_count(&funcs[0]), 0);
    }

    /// New payload: optimal_targets uses functions_reached_count to qualify.
    #[test]
    fn optimal_targets_qualifies_via_count_field() {
        let data = json!({
            "functions": [{
                "name": "counted",
                "hitcount": 0, "arg_count": 2, "cyclomatic_complexity": 30,
                "total_cyclomatic_complexity": 80, "new_unreached_complexity": 50,
                "bb_count": 4,
                "functions_reached_count": 5,
                "reached_by_fuzzers": [],
                "runtime_coverage_percent": 0.0, "source_file": "c.cpp"
            }]
        });
        let result = run_optimal_targets(&data);
        let rows = &result.tables["optimal_targets"];
        assert_eq!(rows.len(), 1, "function with count>0 should qualify");
        assert_eq!(rows[0]["function_name"], "counted");
        assert_eq!(rows[0]["functions_reached_count"], 5);
    }

    /// New payload: optimal_targets excludes a function whose count is 0.
    #[test]
    fn optimal_targets_excludes_zero_count_field() {
        let data = json!({
            "functions": [{
                "name": "empty_f",
                "hitcount": 0, "arg_count": 2, "cyclomatic_complexity": 30,
                "total_cyclomatic_complexity": 80, "new_unreached_complexity": 50,
                "bb_count": 4,
                "functions_reached_count": 0,
                "reached_by_fuzzers": [],
                "runtime_coverage_percent": 0.0, "source_file": "e.cpp"
            }]
        });
        let result = run_optimal_targets(&data);
        assert!(
            result.tables["optimal_targets"].is_empty(),
            "functions_reached_count=0 must be excluded"
        );
    }
}
