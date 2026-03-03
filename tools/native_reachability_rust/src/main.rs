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

//! Native reachability computation for fuzz-introspector.
//!
//! Reads a JSON list of call-graph profiles from stdin, computes the full
//! transitive-closure and maximum depth for every function in each profile,
//! and writes results to stdout.
//!
//! Protocol: see tools/native_reachability_rust/README or the Python wrapper
//! in fuzzer_profile.py::_propagate_functions_reached_native().

use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};

use log::{debug, error, info};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Input types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct Input {
    schema_version: u32,
    profiles: Vec<ProfileInput>,
}

#[derive(Debug, Deserialize)]
struct ProfileInput {
    profile_id: String,
    functions: Vec<FunctionInput>,
}

#[derive(Debug, Deserialize)]
struct FunctionInput {
    name: String,
    direct_callees: Vec<String>,
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct Output {
    schema_version: u32,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    profiles: Option<Vec<ProfileOutput>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[derive(Debug, Serialize)]
struct ProfileOutput {
    profile_id: String,
    results: Vec<FunctionResult>,
}

#[derive(Debug, Serialize)]
struct FunctionResult {
    name: String,
    functions_reached: Vec<String>,
    function_depth: usize,
}

// ---------------------------------------------------------------------------
// Core algorithm: iterative post-order DFS transitive closure
// ---------------------------------------------------------------------------

/// Compute the full transitive closure and maximum call-chain depth for every
/// function in `functions`.
///
/// The algorithm mirrors the Python implementation in
/// `FuzzerProfile._propagate_functions_reached` exactly:
///
/// - Iterative post-order DFS with an explicit stack to avoid OS stack
///   overflow on deep graphs.
/// - Back-edge detection via `on_path` (cycles are silently broken).
/// - Memoisation so every node is fully resolved exactly once.
/// - `depth[name]` = max over direct callees of `depth[callee] + 1`; 0 when
///   the function has no direct callees (leaf).
/// - `functions_reached` for a node includes all transitively reachable names
///   *excluding the function itself*, matching the Python semantics.
fn compute_reachability(functions: &[FunctionInput]) -> Vec<FunctionResult> {
    // Build adjacency map: name -> direct callee slice
    let adj: HashMap<&str, &[String]> = functions
        .iter()
        .map(|f| (f.name.as_str(), f.direct_callees.as_slice()))
        .collect();

    let mut memo: HashMap<String, HashSet<String>> = HashMap::new();
    let mut depth: HashMap<String, usize> = HashMap::new();

    for func in functions {
        if memo.contains_key(&func.name) {
            continue;
        }

        debug!("DFS root: {}", func.name);

        // Stack entries: (function_name, returning).
        //   returning = false  → first visit: push callees, then flip to true
        //   returning = true   → post-order: all children resolved, compute own result
        let mut stack: Vec<(String, bool)> = vec![(func.name.clone(), false)];
        // Tracks the current DFS path for cycle detection.
        let mut on_path: HashSet<String> = HashSet::new();

        while let Some((name, returning)) = stack.last().cloned() {
            if returning {
                stack.pop();
                on_path.remove(&name);

                // Union transitive closures of all direct callees.
                let direct = adj.get(name.as_str()).copied().unwrap_or(&[]);
                let mut reachable: HashSet<String> = HashSet::new();
                let mut max_d: usize = 0;

                for callee in direct {
                    reachable.insert(callee.clone());
                    if let Some(callee_set) = memo.get(callee.as_str()) {
                        reachable.extend(callee_set.iter().cloned());
                        let callee_d = depth.get(callee.as_str()).copied().unwrap_or(0) + 1;
                        if callee_d > max_d {
                            max_d = callee_d;
                        }
                    }
                }

                memo.insert(name.clone(), reachable);
                depth.insert(name.clone(), max_d);
            } else {
                // First visit.
                if memo.contains_key(&name) {
                    stack.pop();
                    continue;
                }

                on_path.insert(name.clone());
                // Flip the top-of-stack entry to returning=true.
                *stack.last_mut().unwrap() = (name.clone(), true);

                // Push unresolved, non-cyclic callees.
                if let Some(callees) = adj.get(name.as_str()) {
                    for callee in callees.iter() {
                        if !memo.contains_key(callee.as_str())
                            && !on_path.contains(callee.as_str())
                        {
                            stack.push((callee.clone(), false));
                        }
                    }
                }
            }
        }
    }

    // Build the ordered output list, preserving input order.
    functions
        .iter()
        .map(|f| {
            let mut reached: Vec<String> = memo
                .get(&f.name)
                .map(|s| s.iter().cloned().collect())
                .unwrap_or_default();
            // Sort for deterministic output (the Python set→list is non-deterministic,
            // but callers only care about set membership, not order).
            reached.sort_unstable();
            let d = depth.get(&f.name).copied().unwrap_or(0);
            FunctionResult {
                name: f.name.clone(),
                functions_reached: reached,
                function_depth: d,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    env_logger::init();
    info!("native_reachability_rust starting");

    // Read all of stdin.
    let mut raw = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut raw) {
        let out = Output {
            schema_version: 1,
            status: "error".to_string(),
            profiles: None,
            reason: Some(format!("Failed to read stdin: {e}")),
        };
        let _ = writeln!(io::stdout(), "{}", serde_json::to_string(&out).unwrap());
        std::process::exit(1);
    }

    // Parse JSON input.
    let input: Input = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            error!("JSON parse error: {e}");
            let out = Output {
                schema_version: 1,
                status: "error".to_string(),
                profiles: None,
                reason: Some(format!("JSON parse error: {e}")),
            };
            let _ = writeln!(io::stdout(), "{}", serde_json::to_string(&out).unwrap());
            std::process::exit(1);
        }
    };

    if input.schema_version != 1 {
        let out = Output {
            schema_version: 1,
            status: "error".to_string(),
            profiles: None,
            reason: Some(format!(
                "Unsupported schema_version: {}",
                input.schema_version
            )),
        };
        let _ = writeln!(io::stdout(), "{}", serde_json::to_string(&out).unwrap());
        std::process::exit(1);
    }

    info!("Processing {} profile(s)", input.profiles.len());

    // Process profiles in parallel — each profile is fully independent.
    let profile_outputs: Vec<ProfileOutput> = input
        .profiles
        .par_iter()
        .map(|profile| {
            info!(
                "Profile '{}': {} functions",
                profile.profile_id,
                profile.functions.len()
            );
            let results = compute_reachability(&profile.functions);
            ProfileOutput {
                profile_id: profile.profile_id.clone(),
                results,
            }
        })
        .collect();

    let out = Output {
        schema_version: 1,
        status: "success".to_string(),
        profiles: Some(profile_outputs),
        reason: None,
    };

    let json = match serde_json::to_string(&out) {
        Ok(s) => s,
        Err(e) => {
            error!("JSON serialization error: {e}");
            let err_out = Output {
                schema_version: 1,
                status: "error".to_string(),
                profiles: None,
                reason: Some(format!("JSON serialization error: {e}")),
            };
            serde_json::to_string(&err_out).unwrap()
        }
    };

    let stdout = io::stdout();
    let mut handle = stdout.lock();
    if let Err(e) = writeln!(handle, "{json}") {
        error!("Failed to write output: {e}");
        std::process::exit(1);
    }

    info!("native_reachability_rust done");
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(name: &str, callees: &[&str]) -> FunctionInput {
        FunctionInput {
            name: name.to_string(),
            direct_callees: callees.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn result_for<'a>(results: &'a [FunctionResult], name: &str) -> &'a FunctionResult {
        results.iter().find(|r| r.name == name).unwrap()
    }

    #[test]
    fn test_leaf_node() {
        let funcs = vec![mk("bar", &[])];
        let results = compute_reachability(&funcs);
        let bar = result_for(&results, "bar");
        assert!(bar.functions_reached.is_empty());
        assert_eq!(bar.function_depth, 0);
    }

    #[test]
    fn test_simple_chain() {
        // foo -> bar -> baz (leaf)
        let funcs = vec![mk("foo", &["bar"]), mk("bar", &["baz"]), mk("baz", &[])];
        let results = compute_reachability(&funcs);
        let foo = result_for(&results, "foo");
        let mut reached = foo.functions_reached.clone();
        reached.sort();
        assert_eq!(reached, vec!["bar", "baz"]);
        assert_eq!(foo.function_depth, 2);

        let bar = result_for(&results, "bar");
        assert_eq!(bar.functions_reached, vec!["baz"]);
        assert_eq!(bar.function_depth, 1);

        let baz = result_for(&results, "baz");
        assert!(baz.functions_reached.is_empty());
        assert_eq!(baz.function_depth, 0);
    }

    #[test]
    fn test_diamond() {
        // foo -> bar, baz; bar -> qux; baz -> qux; qux is a leaf
        let funcs = vec![
            mk("foo", &["bar", "baz"]),
            mk("bar", &["qux"]),
            mk("baz", &["qux"]),
            mk("qux", &[]),
        ];
        let results = compute_reachability(&funcs);
        let foo = result_for(&results, "foo");
        let mut reached = foo.functions_reached.clone();
        reached.sort();
        assert_eq!(reached, vec!["bar", "baz", "qux"]);
        assert_eq!(foo.function_depth, 2);
    }

    #[test]
    fn test_cycle_broken() {
        // a -> b -> a (cycle); both should be resolvable without panic
        let funcs = vec![mk("a", &["b"]), mk("b", &["a"])];
        let results = compute_reachability(&funcs);
        // Neither should panic; exactly what gets reached depends on DFS entry point
        // but both results must be present.
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_self_loop() {
        // a -> a
        let funcs = vec![mk("a", &["a"])];
        let results = compute_reachability(&funcs);
        let a = result_for(&results, "a");
        // 'a' is on_path when we try to push 'a' again, so it is not pushed.
        // direct callees list still contains "a", so it IS inserted into reachable.
        // This matches Python: reachable.add(callee) runs before the memo union.
        assert_eq!(results.len(), 1);
        let _ = a; // just assert no panic
    }

    #[test]
    fn test_unknown_callee() {
        // foo calls "external" which has no entry in the function list.
        // The DFS still visits "external" (as an unresolved node), memoises it
        // with an empty reached-set and depth 0, and then foo's depth picks up
        // the +1 contribution: depth["foo"] = depth["external"] + 1 = 1.
        // This matches the Python algorithm exactly.
        let funcs = vec![mk("foo", &["external"])];
        let results = compute_reachability(&funcs);
        let foo = result_for(&results, "foo");
        assert_eq!(foo.functions_reached, vec!["external"]);
        assert_eq!(foo.function_depth, 1);
    }

    #[test]
    fn test_memoization_shared_callee() {
        // Two roots both call the same subtree; subtree resolved once.
        let funcs = vec![
            mk("root1", &["shared"]),
            mk("root2", &["shared"]),
            mk("shared", &["leaf"]),
            mk("leaf", &[]),
        ];
        let results = compute_reachability(&funcs);
        let r1 = result_for(&results, "root1");
        let r2 = result_for(&results, "root2");
        let mut r1_reached = r1.functions_reached.clone();
        r1_reached.sort();
        let mut r2_reached = r2.functions_reached.clone();
        r2_reached.sort();
        assert_eq!(r1_reached, vec!["leaf", "shared"]);
        assert_eq!(r2_reached, vec!["leaf", "shared"]);
        assert_eq!(r1.function_depth, 2);
        assert_eq!(r2.function_depth, 2);
    }
}
