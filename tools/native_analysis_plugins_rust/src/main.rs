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
#[derive(Debug, Clone)]
struct FunctionEntry {
    name: String,
    hitcount: u64,
    arg_count: u64,
    cyclomatic_complexity: i64,
    total_cyclomatic_complexity: i64,
    new_unreached_complexity: i64,
    bb_count: u64,
    /// Length of `functions_reached` from legacy payloads.
    functions_reached_len: usize,
    /// Explicit count supplied by new Python payload (avoids sending the full
    /// list).  Zero means "not supplied" — callers must use
    /// `effective_reached_count()` instead of reading this field directly.
    functions_reached_count: usize,
    reached_by_fuzzers: Vec<String>,
    runtime_coverage_percent: f64,
    is_accessible: bool,
    is_jvm_library: bool,
    is_enum: bool,
    source_file: String,
    incoming_references: Vec<String>,
}

impl Default for FunctionEntry {
    fn default() -> Self {
        Self {
            name: String::new(),
            hitcount: 0,
            arg_count: 0,
            cyclomatic_complexity: 0,
            total_cyclomatic_complexity: 0,
            new_unreached_complexity: 0,
            bb_count: 0,
            functions_reached_len: 0,
            functions_reached_count: 0,
            reached_by_fuzzers: Vec::new(),
            runtime_coverage_percent: 0.0,
            is_accessible: true, // Match Python: getattr(fp, "is_accessible", True)
            is_jvm_library: false,
            is_enum: false,
            source_file: String::new(),
            incoming_references: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct FunctionTableEntry {
    name: String,
    total_cyclomatic_complexity: i64,
}

#[derive(Debug, Clone, Copy, Default)]
struct FunctionFieldMask {
    name: bool,
    hitcount: bool,
    arg_count: bool,
    cyclomatic_complexity: bool,
    total_cyclomatic_complexity: bool,
    new_unreached_complexity: bool,
    bb_count: bool,
    functions_reached_len_or_count: bool,
    reached_by_fuzzers: bool,
    runtime_coverage_percent: bool,
    is_accessible: bool,
    is_jvm_library: bool,
    is_enum: bool,
    source_file: bool,
    incoming_references: bool,
}

fn required_function_fields(plugins: &[String]) -> FunctionFieldMask {
    let mut fields = FunctionFieldMask::default();

    for plugin in plugins {
        match plugin.as_str() {
            "optimal_targets" => {
                fields.name = true;
                fields.hitcount = true;
                fields.arg_count = true;
                fields.cyclomatic_complexity = true;
                fields.total_cyclomatic_complexity = true;
                fields.new_unreached_complexity = true;
                fields.bb_count = true;
                fields.functions_reached_len_or_count = true;
                fields.source_file = true;
            }
            "runtime_coverage_analysis" => {
                fields.name = true;
                fields.hitcount = true;
                fields.new_unreached_complexity = true;
                fields.total_cyclomatic_complexity = true;
                fields.reached_by_fuzzers = true;
            }
            "calltree_analysis" => {
                fields.hitcount = true;
            }
            "sink_coverage_analysis" => {
                fields.name = true;
                fields.reached_by_fuzzers = true;
                fields.source_file = true;
                fields.incoming_references = true;
            }
            "function_table" => {
                fields.name = true;
                fields.total_cyclomatic_complexity = true;
            }
            "far_reach_low_coverage_analysis" => {
                fields.name = true;
                fields.cyclomatic_complexity = true;
                fields.runtime_coverage_percent = true;
                fields.is_accessible = true;
                fields.is_jvm_library = true;
                fields.is_enum = true;
            }
            _ => {}
        }
    }

    fields
}

fn parse_u64_field(obj: &serde_json::Map<String, JsonValue>, key: &str) -> u64 {
    obj.get(key).and_then(JsonValue::as_u64).unwrap_or(0)
}

fn parse_i64_field(obj: &serde_json::Map<String, JsonValue>, key: &str) -> i64 {
    obj.get(key).and_then(JsonValue::as_i64).unwrap_or(0)
}

fn parse_f64_field(obj: &serde_json::Map<String, JsonValue>, key: &str) -> f64 {
    obj.get(key).and_then(JsonValue::as_f64).unwrap_or(0.0)
}

fn parse_bool_field(obj: &serde_json::Map<String, JsonValue>, key: &str) -> bool {
    obj.get(key).and_then(JsonValue::as_bool).unwrap_or(false)
}

fn parse_string_field(obj: &serde_json::Map<String, JsonValue>, key: &str) -> String {
    obj.get(key)
        .and_then(JsonValue::as_str)
        .unwrap_or_default()
        .to_string()
}

fn parse_string_vec_field(obj: &serde_json::Map<String, JsonValue>, key: &str) -> Vec<String> {
    obj.get(key)
        .and_then(JsonValue::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(JsonValue::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn parse_reached_counters(obj: &serde_json::Map<String, JsonValue>) -> (usize, usize) {
    let explicit_count = obj
        .get("functions_reached_count")
        .and_then(JsonValue::as_u64)
        .map(|n| n as usize)
        .unwrap_or(0);
    let reached_len = obj
        .get("functions_reached")
        .and_then(JsonValue::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    (explicit_count, reached_len)
}

/// Parse `project_data["functions"]` into a `Vec<FunctionEntry>`.
/// Returns an empty vec if the key is absent or malformed.
fn parse_functions(project_data: &JsonValue, requested_plugins: &[String]) -> Vec<FunctionEntry> {
    let fields = required_function_fields(requested_plugins);

    project_data
        .get("functions")
        .and_then(JsonValue::as_array)
        .map(|functions| {
            functions
                .iter()
                .map(|function_value| {
                    let mut entry = FunctionEntry::default();
                    if let Some(obj) = function_value.as_object() {
                        if fields.name {
                            entry.name = parse_string_field(obj, "name");
                        }
                        if fields.hitcount {
                            entry.hitcount = parse_u64_field(obj, "hitcount");
                        }
                        if fields.arg_count {
                            entry.arg_count = parse_u64_field(obj, "arg_count");
                        }
                        if fields.cyclomatic_complexity {
                            entry.cyclomatic_complexity =
                                parse_i64_field(obj, "cyclomatic_complexity");
                        }
                        if fields.total_cyclomatic_complexity {
                            entry.total_cyclomatic_complexity =
                                parse_i64_field(obj, "total_cyclomatic_complexity");
                        }
                        if fields.new_unreached_complexity {
                            entry.new_unreached_complexity =
                                parse_i64_field(obj, "new_unreached_complexity");
                        }
                        if fields.bb_count {
                            entry.bb_count = parse_u64_field(obj, "bb_count");
                        }
                        if fields.functions_reached_len_or_count {
                            (entry.functions_reached_count, entry.functions_reached_len) =
                                parse_reached_counters(obj);
                        }
                        if fields.reached_by_fuzzers {
                            entry.reached_by_fuzzers = parse_string_vec_field(obj, "reached_by_fuzzers");
                        }
                        if fields.runtime_coverage_percent {
                            entry.runtime_coverage_percent =
                                parse_f64_field(obj, "runtime_coverage_percent");
                        }
                        if fields.is_accessible {
                            entry.is_accessible = obj.get("is_accessible")
                                .and_then(JsonValue::as_bool)
                                .unwrap_or(true);  // Match Python: getattr(fp, "is_accessible", True)
                        }
                        if fields.is_jvm_library {
                            entry.is_jvm_library = parse_bool_field(obj, "is_jvm_library");
                        }
                        if fields.is_enum {
                            entry.is_enum = parse_bool_field(obj, "is_enum");
                        }
                        if fields.source_file {
                            entry.source_file = parse_string_field(obj, "source_file");
                        }
                        if fields.incoming_references {
                            entry.incoming_references =
                                parse_string_vec_field(obj, "incoming_references");
                        }
                    }
                    entry
                })
                .collect()
        })
        .unwrap_or_default()
}

fn parse_function_table_entries(project_data: &JsonValue) -> Vec<FunctionTableEntry> {
    project_data
        .get("functions")
        .and_then(JsonValue::as_array)
        .map(|functions| {
            functions
                .iter()
                .map(|function_value| {
                    let mut entry = FunctionTableEntry::default();
                    if let Some(obj) = function_value.as_object() {
                        entry.name = parse_string_field(obj, "name");
                        entry.total_cyclomatic_complexity =
                            parse_i64_field(obj, "total_cyclomatic_complexity");
                    }
                    entry
                })
                .collect()
        })
        .unwrap_or_default()
}

fn plugin_requires_full_functions_parse(plugin: &str) -> bool {
    matches!(
        plugin,
        "optimal_targets"
            | "runtime_coverage_analysis"
            | "calltree_analysis"
            | "sink_coverage_analysis"
            | "far_reach_low_coverage_analysis"
    )
}

fn derive_function_table_entries_from_functions(
    functions: &[FunctionEntry],
) -> Vec<FunctionTableEntry> {
    functions
        .iter()
        .map(|function| FunctionTableEntry {
            name: function.name.clone(),
            total_cyclomatic_complexity: function.total_cyclomatic_complexity,
        })
        .collect()
}

/// Request-scoped parsed data shared by all plugin handlers.
#[derive(Debug)]
struct ParsedProjectData {
    functions: Vec<FunctionEntry>,
    function_table_entries: Vec<FunctionTableEntry>,
    target_lang: Option<String>,
}

/// Parse the subset of `project_data` used by Rust-native plugins once.
fn parse_project_data(project_data: &JsonValue, requested_plugins: &[String]) -> ParsedProjectData {
    let function_table_requested = requested_plugins.iter().any(|p| p == "function_table");
    let full_functions_requested = requested_plugins
        .iter()
        .any(|p| plugin_requires_full_functions_parse(p));

    let functions = if full_functions_requested {
        parse_functions(project_data, requested_plugins)
    } else {
        Vec::new()
    };

    let function_table_entries = if function_table_requested {
        if full_functions_requested {
            derive_function_table_entries_from_functions(&functions)
        } else {
            parse_function_table_entries(project_data)
        }
    } else {
        Vec::new()
    };

    ParsedProjectData {
        functions,
        function_table_entries,
        target_lang: project_data
            .get("target_lang")
            .and_then(JsonValue::as_str)
            .map(str::to_string),
    }
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
// Each `run_*` function receives request-scoped parsed project data and
// returns a PluginResult.

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
    if f.functions_reached_count > 0 || f.functions_reached_len == 0 {
        f.functions_reached_count
    } else {
        f.functions_reached_len
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
fn run_optimal_targets(parsed_data: &ParsedProjectData) -> PluginResult {
    log::debug!("[optimal_targets] running real implementation");

    let functions = &parsed_data.functions;

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
fn run_runtime_coverage_analysis(parsed_data: &ParsedProjectData) -> PluginResult {
    log::debug!("[runtime_coverage_analysis] running real implementation");

    let functions = &parsed_data.functions;

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
fn run_calltree_analysis(parsed_data: &ParsedProjectData) -> PluginResult {
    log::debug!("[calltree_analysis] running real implementation");

    let functions = &parsed_data.functions;
    let target_lang = parsed_data
        .target_lang
        .clone()
        .unwrap_or_else(|| "unknown".to_string());

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
fn run_sink_coverage_analysis(parsed_data: &ParsedProjectData) -> PluginResult {
    log::debug!("[sink_coverage_analysis] running");

    let functions = &parsed_data.functions;
    let target_lang = parsed_data.target_lang.as_deref().unwrap_or("c-cpp");

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

/// `function_table` plugin: return all project functions sorted by
/// `total_cyclomatic_complexity` descending.
///
/// Used by `html_report.py` `create_all_function_table()` to avoid the Python
/// dict-order iteration when building the "all functions" HTML table.
/// Returns only ordered function names (compact payload/response).
fn run_function_table(parsed_data: &ParsedProjectData) -> PluginResult {
    log::debug!("[function_table] running");

    let function_table_entries = &parsed_data.function_table_entries;
    let total = function_table_entries.len();

    // Sort by total_cyclomatic_complexity descending; stable to keep original
    // insertion order for ties.
    let mut sorted: Vec<&FunctionTableEntry> = function_table_entries.iter().collect();
    sorted.sort_by(|a, b| b.total_cyclomatic_complexity.cmp(&a.total_cyclomatic_complexity));

    let top_complexity = sorted
        .first()
        .map(|f| f.total_cyclomatic_complexity)
        .unwrap_or(0);

    let ordered_names: Vec<JsonValue> = sorted
        .iter()
        .map(|f| JsonValue::String(f.name.clone()))
        .collect();

    let summary = format!(
        "function_table: {} function(s), top total_cyclomatic_complexity={}",
        total, top_complexity
    );
    log::debug!("[function_table] {}", summary);

    let mut tables = HashMap::new();
    tables.insert("ordered_function_names".to_string(), ordered_names);
    PluginResult { tables, summary }
}

/// `far_reach_low_coverage_analysis`: select candidate functions with low
/// runtime coverage and high structural complexity.
///
/// This ports `_get_functions_of_interest()` from
/// `far_reach_low_coverage_analyser.py` except for `min_complexity`, which is
/// a runtime CLI flag handled on the Python side to preserve parity.
fn run_far_reach_low_coverage_analysis(parsed_data: &ParsedProjectData) -> PluginResult {
    log::debug!("[far_reach_low_coverage_analysis] running");

    let mut candidates: Vec<(usize, &FunctionEntry)> = parsed_data
        .functions
        .iter()
        .enumerate()
        .filter(|(_, f)| {
            if !f.is_accessible || f.is_jvm_library || f.is_enum {
                return false;
            }
            if f.runtime_coverage_percent > 20.0 {
                return false;
            }
            true
        })
        .collect();

    // Match Python order from `_get_functions_of_interest`:
    //   1) cyclomatic_complexity descending
    //   2) runtime coverage ascending
    // Keep original input order for total ties.
    candidates.sort_by(|(idx_a, a), (idx_b, b)| {
        b.cyclomatic_complexity
            .cmp(&a.cyclomatic_complexity)
            .then_with(|| {
                a.runtime_coverage_percent
                    .total_cmp(&b.runtime_coverage_percent)
            })
            .then_with(|| idx_a.cmp(idx_b))
    });

    let rows: Vec<JsonValue> = candidates
        .into_iter()
        .map(|(_, f)| {
            serde_json::json!({
                "function_name": f.name,
            })
        })
        .collect();

    let summary = format!(
        "far_reach_low_coverage_analysis: {} candidate(s)",
        rows.len()
    );
    let mut tables = HashMap::new();
    tables.insert("far_reach_candidates".to_string(), rows);
    PluginResult { tables, summary }
}

/// Dispatcher: route a plugin name to its handler function.
///
/// Returns `None` for unknown plugin names so the caller can log and skip.
fn dispatch_plugin(name: &str, parsed_data: &ParsedProjectData) -> Option<PluginResult> {
    match name {
        "optimal_targets" => Some(run_optimal_targets(parsed_data)),
        "runtime_coverage_analysis" => Some(run_runtime_coverage_analysis(parsed_data)),
        "calltree_analysis" => Some(run_calltree_analysis(parsed_data)),
        "sink_coverage_analysis" => Some(run_sink_coverage_analysis(parsed_data)),
        "function_table" => Some(run_function_table(parsed_data)),
        "far_reach_low_coverage_analysis" => {
            Some(run_far_reach_low_coverage_analysis(parsed_data))
        }
        _ => {
            log::warn!("unknown plugin requested: {:?}", name);
            None
        }
    }
}

type ProjectDataParser = fn(&JsonValue, &[String]) -> ParsedProjectData;

fn run_request_with_parser(
    request: &Request,
    parse_project_data_fn: ProjectDataParser,
) -> HashMap<String, PluginResult> {
    let parsed_data = parse_project_data_fn(&request.project_data, &request.plugins);

    // Collect (name, result) pairs in parallel; rayon preserves input order.
    request
        .plugins
        .par_iter()
        .filter_map(|plugin_name| {
            dispatch_plugin(plugin_name, &parsed_data).map(|result| (plugin_name.clone(), result))
        })
        .collect()
}

// ── Request execution ────────────────────────────────────────────────────────

/// Run all requested plugins, using rayon for parallel dispatch.
///
/// Plugin names that are not recognised are silently omitted from `results`.
fn run_request(request: &Request) -> HashMap<String, PluginResult> {
    run_request_with_parser(request, parse_project_data)
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
    use std::sync::atomic::{AtomicUsize, Ordering};

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

    fn parsed(data: &JsonValue) -> ParsedProjectData {
        let plugins = vec![
            "optimal_targets".to_string(),
            "runtime_coverage_analysis".to_string(),
            "calltree_analysis".to_string(),
            "sink_coverage_analysis".to_string(),
            "function_table".to_string(),
            "far_reach_low_coverage_analysis".to_string(),
        ];
        parse_project_data(data, &plugins)
    }

    // ── dispatch tests ───────────────────────────────────────────────────────

    #[test]
    fn dispatch_optimal_targets_returns_some() {
        let parsed_data = parsed(&json!({}));
        let result = dispatch_plugin("optimal_targets", &parsed_data);
        assert!(result.is_some());
    }

    #[test]
    fn dispatch_runtime_coverage_analysis_returns_some() {
        let parsed_data = parsed(&json!({}));
        let result = dispatch_plugin("runtime_coverage_analysis", &parsed_data);
        assert!(result.is_some());
    }

    #[test]
    fn dispatch_calltree_analysis_returns_some() {
        let parsed_data = parsed(&json!({}));
        let result = dispatch_plugin("calltree_analysis", &parsed_data);
        assert!(result.is_some());
    }

    #[test]
    fn dispatch_unknown_plugin_returns_none() {
        let parsed_data = parsed(&json!({}));
        let result = dispatch_plugin("no_such_plugin", &parsed_data);
        assert!(result.is_none());
    }

    #[test]
    fn dispatch_far_reach_low_coverage_analysis_returns_some() {
        let parsed_data = parsed(&json!({}));
        let result = dispatch_plugin("far_reach_low_coverage_analysis", &parsed_data);
        assert!(result.is_some());
    }

    #[test]
    fn function_table_returns_compact_ordered_names() {
        let data = sample_project_data();
        let parsed_data = parsed(&data);
        let result = run_function_table(&parsed_data);
        let names = &result.tables["ordered_function_names"];

        assert_eq!(names.len(), 3);
        assert_eq!(names[0], "foo");
        assert_eq!(names[1], "bar");
        assert_eq!(names[2], "main");
    }

    #[test]
    fn parse_project_data_function_table_only_populates_compact_entries() {
        let data = json!({
            "functions": [
                {
                    "name": "foo",
                    "total_cyclomatic_complexity": 80
                },
                {
                    "name": "bar"
                }
            ]
        });
        let plugins = vec!["function_table".to_string()];
        let parsed_data = parse_project_data(&data, &plugins);

        assert!(parsed_data.functions.is_empty());
        assert_eq!(parsed_data.function_table_entries.len(), 2);
        assert_eq!(parsed_data.function_table_entries[0].name, "foo");
        assert_eq!(
            parsed_data.function_table_entries[0].total_cyclomatic_complexity,
            80
        );
        assert_eq!(parsed_data.function_table_entries[1].name, "bar");
        assert_eq!(
            parsed_data.function_table_entries[1].total_cyclomatic_complexity,
            0
        );
    }

    #[test]
    fn parse_project_data_unknown_plus_function_table_does_not_parse_full_functions() {
        let data = json!({
            "functions": [
                {
                    "name": "foo",
                    "total_cyclomatic_complexity": 80,
                    "hitcount": "malformed"
                },
                {
                    "name": "bar",
                    "total_cyclomatic_complexity": 30
                }
            ]
        });
        let plugins = vec!["function_table".to_string(), "unknown_plugin".to_string()];
        let parsed_data = parse_project_data(&data, &plugins);

        assert!(parsed_data.functions.is_empty());
        assert_eq!(parsed_data.function_table_entries.len(), 2);
        assert_eq!(parsed_data.function_table_entries[0].name, "foo");
        assert_eq!(
            parsed_data.function_table_entries[0].total_cyclomatic_complexity,
            80
        );
        assert_eq!(parsed_data.function_table_entries[1].name, "bar");
    }

    #[test]
    fn parse_project_data_mixed_request_derives_function_table_from_functions() {
        let data = json!({
            "functions": [
                {
                    "name": "foo",
                    "hitcount": 0,
                    "arg_count": 2,
                    "cyclomatic_complexity": 25,
                    "total_cyclomatic_complexity": 80,
                    "new_unreached_complexity": 60,
                    "bb_count": 5,
                    "functions_reached": ["bar"],
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
                    "source_file": "bar.cpp"
                }
            ]
        });
        let plugins = vec!["optimal_targets".to_string(), "function_table".to_string()];
        let parsed_data = parse_project_data(&data, &plugins);

        assert_eq!(parsed_data.functions.len(), 2);
        assert_eq!(parsed_data.function_table_entries.len(), 2);

        let result = run_function_table(&parsed_data);
        let names = &result.tables["ordered_function_names"];
        assert_eq!(names.len(), 2);
        assert_eq!(names[0], "foo");
        assert_eq!(names[1], "bar");
    }

    // ── optimal_targets tests ────────────────────────────────────────────────

    #[test]
    fn optimal_targets_has_expected_table_key() {
        let result = run_optimal_targets(&parsed(&json!({})));
        assert!(result.tables.contains_key("optimal_targets"));
        assert!(!result.summary.is_empty());
    }

    #[test]
    fn optimal_targets_empty_functions_returns_empty_table() {
        let result = run_optimal_targets(&parsed(&json!({"functions": []})));
        assert!(result.tables["optimal_targets"].is_empty());
    }

    #[test]
    fn optimal_targets_selects_foo_not_main_or_bar() {
        let data = sample_project_data();
        let result = run_optimal_targets(&parsed(&data));
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
        let result = run_optimal_targets(&parsed(&data));
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
        let result = run_optimal_targets(&parsed(&data));
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
        let result = run_optimal_targets(&parsed(&data));
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
        let result = run_optimal_targets(&parsed(&data));
        let rows = &result.tables["optimal_targets"];
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["function_name"], "beta", "beta has higher nuc");
        assert_eq!(rows[1]["function_name"], "alpha");
    }

    // ── runtime_coverage_analysis tests ─────────────────────────────────────

    #[test]
    fn runtime_coverage_has_expected_table_key() {
        let result = run_runtime_coverage_analysis(&parsed(&json!({})));
        assert!(result.tables.contains_key("runtime_coverage"));
        assert!(!result.summary.is_empty());
    }

    #[test]
    fn runtime_coverage_empty_functions_returns_empty_table() {
        let result = run_runtime_coverage_analysis(&parsed(&json!({"functions": []})));
        assert!(result.tables["runtime_coverage"].is_empty());
    }

    #[test]
    fn runtime_coverage_selects_bar_not_foo_or_main() {
        let data = sample_project_data();
        let result = run_runtime_coverage_analysis(&parsed(&data));
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
        let result = run_runtime_coverage_analysis(&parsed(&data));
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
        let result = run_runtime_coverage_analysis(&parsed(&data));
        assert!(
            result.tables["runtime_coverage"].is_empty(),
            "nuc<=20 must be excluded"
        );
    }

    // ── far_reach_low_coverage_analysis tests ───────────────────────────────

    #[test]
    fn far_reach_low_coverage_has_expected_table_key() {
        let result = run_far_reach_low_coverage_analysis(&parsed(&json!({})));
        assert!(result.tables.contains_key("far_reach_candidates"));
        assert!(!result.summary.is_empty());
    }

    #[test]
    fn far_reach_low_coverage_filters_and_sorts_like_python_path() {
        let data = json!({
            "functions": [
                {
                    "name": "skip_high_cov",
                    "cyclomatic_complexity": 100,
                    "runtime_coverage_percent": 70.0,
                    "is_accessible": true,
                    "is_jvm_library": false,
                    "is_enum": false
                },
                {
                    "name": "skip_enum",
                    "cyclomatic_complexity": 50,
                    "runtime_coverage_percent": 0.0,
                    "is_accessible": true,
                    "is_jvm_library": false,
                    "is_enum": true
                },
                {
                    "name": "tie_cov_second",
                    "cyclomatic_complexity": 30,
                    "runtime_coverage_percent": 10.0,
                    "is_accessible": true,
                    "is_jvm_library": false,
                    "is_enum": false
                },
                {
                    "name": "highest_cc",
                    "cyclomatic_complexity": 70,
                    "runtime_coverage_percent": 15.0,
                    "is_accessible": true,
                    "is_jvm_library": false,
                    "is_enum": false
                },
                {
                    "name": "tie_cov_first",
                    "cyclomatic_complexity": 30,
                    "runtime_coverage_percent": 5.0,
                    "is_accessible": true,
                    "is_jvm_library": false,
                    "is_enum": false
                }
            ]
        });

        let result = run_far_reach_low_coverage_analysis(&parsed(&data));
        let rows = &result.tables["far_reach_candidates"];
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0]["function_name"], "highest_cc");
        assert_eq!(rows[1]["function_name"], "tie_cov_first");
        assert_eq!(rows[2]["function_name"], "tie_cov_second");
    }

    #[test]
    fn far_reach_missing_is_accessible_defaults_to_accessible() {
        let data = json!({
            "functions": [{
                "name": "no_accessible_field",
                "cyclomatic_complexity": 50,
                "runtime_coverage_percent": 5.0,
                "is_jvm_library": false,
                "is_enum": false
            }]
        });
        let result = run_far_reach_low_coverage_analysis(&parsed(&data));
        let rows = &result.tables["far_reach_candidates"];
        assert_eq!(rows.len(), 1, "missing is_accessible should default to true");
    }

    // ── calltree_analysis tests ───────────────────────────────────────────────

    #[test]
    fn calltree_analysis_has_expected_table_key() {
        let result = run_calltree_analysis(&parsed(&json!({})));
        assert!(result.tables.contains_key("calltree_nodes"));
        assert!(!result.summary.is_empty());
    }

    #[test]
    fn calltree_analysis_empty_project_returns_one_summary_row() {
        let data = json!({"functions": [], "target_lang": "c-cpp"});
        let result = run_calltree_analysis(&parsed(&data));
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
        let result = run_calltree_analysis(&parsed(&data));
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
        let result = run_calltree_analysis(&parsed(&data));
        let rows = &result.tables["calltree_nodes"];
        assert_eq!(rows[0]["reach_percentage"], 0.0);
    }

    // ── parallel dispatch tests ──────────────────────────────────────────────

    static PARSE_INVOCATIONS: AtomicUsize = AtomicUsize::new(0);

    fn counting_parse_project_data(
        project_data: &JsonValue,
        requested_plugins: &[String],
    ) -> ParsedProjectData {
        PARSE_INVOCATIONS.fetch_add(1, Ordering::SeqCst);
        parse_project_data(project_data, requested_plugins)
    }

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

    #[test]
    fn run_request_parses_project_data_once_for_multiple_plugins() {
        PARSE_INVOCATIONS.store(0, Ordering::SeqCst);
        let request = Request {
            schema_version: 1,
            plugins: vec![
                "optimal_targets".to_string(),
                "runtime_coverage_analysis".to_string(),
                "calltree_analysis".to_string(),
            ],
            project_data: sample_project_data(),
        };

        let results = run_request_with_parser(&request, counting_parse_project_data);
        assert_eq!(results.len(), 3);
        assert_eq!(PARSE_INVOCATIONS.load(Ordering::SeqCst), 1);
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
        let plugins = vec!["function_table".to_string()];
        assert!(parse_functions(&data, &plugins).is_empty());
    }

    #[test]
    fn parse_functions_handles_defaults_for_missing_fields() {
        let data = json!({"functions": [{"name": "minimal"}]});
        let plugins = vec!["optimal_targets".to_string()];
        let funcs = parse_functions(&data, &plugins);
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0].name, "minimal");
        assert_eq!(funcs[0].hitcount, 0);
        assert_eq!(funcs[0].arg_count, 0);
    }

    #[test]
    fn parse_functions_ignores_malformed_unused_fields_for_function_table() {
        let data = json!({
            "functions": [{
                "name": "kept",
                "total_cyclomatic_complexity": 99,
                "incoming_references": [1, 2, 3],
                "reached_by_fuzzers": [{"bad": "type"}]
            }]
        });
        let plugins = vec!["function_table".to_string()];
        let funcs = parse_functions(&data, &plugins);
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0].name, "kept");
        assert_eq!(funcs[0].total_cyclomatic_complexity, 99);
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
        let plugins = vec!["optimal_targets".to_string()];
        let funcs = parse_functions(&data, &plugins);
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
        let plugins = vec!["optimal_targets".to_string()];
        let funcs = parse_functions(&data, &plugins);
        assert_eq!(effective_reached_count(&funcs[0]), 3);
    }

    /// Both absent → zero (genuinely empty).
    #[test]
    fn effective_reached_count_zero_when_both_absent() {
        let data = json!({"functions": [{"name": "f"}]});
        let plugins = vec!["optimal_targets".to_string()];
        let funcs = parse_functions(&data, &plugins);
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
        let result = run_optimal_targets(&parsed(&data));
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
        let result = run_optimal_targets(&parsed(&data));
        assert!(
            result.tables["optimal_targets"].is_empty(),
            "functions_reached_count=0 must be excluded"
        );
    }
}
