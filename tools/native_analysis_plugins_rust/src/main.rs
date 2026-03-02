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

// ── Plugin stubs ─────────────────────────────────────────────────────────────
//
// Each `run_*` function receives a reference to the project_data JSON value
// and returns a PluginResult.  The current implementations are intentional
// stubs that return empty-but-schema-valid results so that the Python
// integration path can be tested end-to-end.  Real implementations can be
// dropped in per-plugin in Sprint 4 without changing the dispatch or
// serialisation layer.

/// Stub for the `optimal_targets` analysis.
///
/// Real implementation would rank functions by unreached complexity and
/// return candidate fuzz target rows.
fn run_optimal_targets(_project_data: &JsonValue) -> PluginResult {
    log::debug!("[optimal_targets] stub: returning empty result");
    PluginResult {
        tables: {
            let mut t = HashMap::new();
            // Schema: each row would have function_name, complexity, ...
            t.insert("optimal_targets".to_string(), Vec::new());
            t
        },
        summary: "optimal_targets stub (no results yet)".to_string(),
    }
}

/// Stub for the `runtime_coverage_analysis` analysis.
///
/// Real implementation would aggregate per-function runtime hit-counts and
/// highlight uncovered, reachable code.
fn run_runtime_coverage_analysis(_project_data: &JsonValue) -> PluginResult {
    log::debug!("[runtime_coverage_analysis] stub: returning empty result");
    PluginResult {
        tables: {
            let mut t = HashMap::new();
            // Schema: each row would have function_name, hit_count, coverage_pct, ...
            t.insert("runtime_coverage".to_string(), Vec::new());
            t
        },
        summary: "runtime_coverage_analysis stub (no results yet)".to_string(),
    }
}

/// Stub for the `calltree_analysis` analysis.
///
/// Real implementation would traverse the call-graph represented in
/// project_data and annotate nodes with coverage colours / blockers.
fn run_calltree_analysis(_project_data: &JsonValue) -> PluginResult {
    log::debug!("[calltree_analysis] stub: returning empty result");
    PluginResult {
        tables: {
            let mut t = HashMap::new();
            // Schema: each row would have node_id, depth, hit_count, color, ...
            t.insert("calltree_nodes".to_string(), Vec::new());
            t
        },
        summary: "calltree_analysis stub (no results yet)".to_string(),
    }
}

/// Dispatcher: route a plugin name to its handler function.
///
/// Returns `None` for unknown plugin names so the caller can log and skip.
fn dispatch_plugin(name: &str, project_data: &JsonValue) -> Option<PluginResult> {
    match name {
        "optimal_targets" => Some(run_optimal_targets(project_data)),
        "runtime_coverage_analysis" => Some(run_runtime_coverage_analysis(project_data)),
        "calltree_analysis" => Some(run_calltree_analysis(project_data)),
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

    // ── stub schema tests ────────────────────────────────────────────────────

    #[test]
    fn optimal_targets_stub_has_expected_table_key() {
        let result = run_optimal_targets(&json!({}));
        assert!(result.tables.contains_key("optimal_targets"));
        assert!(result.tables["optimal_targets"].is_empty());
        assert!(!result.summary.is_empty());
    }

    #[test]
    fn runtime_coverage_stub_has_expected_table_key() {
        let result = run_runtime_coverage_analysis(&json!({}));
        assert!(result.tables.contains_key("runtime_coverage"));
        assert!(result.tables["runtime_coverage"].is_empty());
        assert!(!result.summary.is_empty());
    }

    #[test]
    fn calltree_analysis_stub_has_expected_table_key() {
        let result = run_calltree_analysis(&json!({}));
        assert!(result.tables.contains_key("calltree_nodes"));
        assert!(result.tables["calltree_nodes"].is_empty());
        assert!(!result.summary.is_empty());
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
}
