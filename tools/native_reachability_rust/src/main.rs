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
// Core algorithm: Tarjan SCC + DAG condensation transitive closure
// ---------------------------------------------------------------------------

/// Compute the full transitive closure and maximum call-chain depth for every
/// function in `functions` using Tarjan's SCC algorithm.
///
/// Algorithm:
/// 1. Build adjacency map covering both declared functions and any external
///    callees they reference.
/// 2. Run Tarjan's iterative SCC algorithm over all nodes.  Tarjan naturally
///    yields SCCs in reverse topological order (leaves/sinks first), which is
///    exactly the order needed for the bottom-up union pass.
/// 3. Condense the call graph into a DAG of SCCs.
/// 4. Process SCCs in Tarjan output order: each SCC's reachable set = all
///    members ∪ union of all successor SCCs' reachable sets.
/// 5. Write back: every function gets
///    `functions_reached = reachable_set − {self}` and
///    `function_depth = depth_of_its_scc`.
///
/// Correctness for cycles: all functions in the same SCC share the same
/// reachable set (they can all reach each other), so no function ever gets
/// a truncated result due to a cycle.
fn compute_reachability(functions: &[FunctionInput]) -> Vec<FunctionResult> {
    // ------------------------------------------------------------------
    // Step 1 – build full adjacency (declared nodes + external callees).
    // ------------------------------------------------------------------
    // adj_owned: name -> list of direct callees (owned strings for external nodes)
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();

    for f in functions {
        let callees: Vec<&str> = f.direct_callees.iter().map(|s| s.as_str()).collect();
        adj.insert(f.name.as_str(), callees);
    }

    // Collect all node names (functions in adj + external callees not in adj).
    let mut all_nodes: Vec<&str> = Vec::new();
    let mut seen_nodes: HashSet<&str> = HashSet::new();
    for f in functions {
        if seen_nodes.insert(f.name.as_str()) {
            all_nodes.push(f.name.as_str());
        }
        for callee in &f.direct_callees {
            if seen_nodes.insert(callee.as_str()) {
                all_nodes.push(callee.as_str());
            }
        }
    }
    // Ensure external nodes have an entry (empty adjacency list).
    for &node in &all_nodes {
        adj.entry(node).or_insert_with(Vec::new);
    }

    // ------------------------------------------------------------------
    // Step 2 – iterative Tarjan's SCC.
    // Yields SCCs in reverse topological order (sinks first).
    // ------------------------------------------------------------------
    let mut index_map: HashMap<&str, usize> = HashMap::new();
    let mut lowlink: HashMap<&str, usize> = HashMap::new();
    let mut on_stack: HashSet<&str> = HashSet::new();
    let mut tarjan_stack: Vec<&str> = Vec::new();
    let mut index_counter: usize = 0;
    let mut sccs: Vec<Vec<String>> = Vec::new();

    // Explicit DFS call-stack entry: (node, iterator_position_over_children)
    // We store the children as a Vec and keep a cursor index.
    struct Frame<'a> {
        node: &'a str,
        children: Vec<&'a str>,
        child_idx: usize,
    }

    for &start in &all_nodes {
        if index_map.contains_key(start) {
            continue;
        }

        // Push the start node.
        index_map.insert(start, index_counter);
        lowlink.insert(start, index_counter);
        index_counter += 1;
        tarjan_stack.push(start);
        on_stack.insert(start);

        let children = adj.get(start).cloned().unwrap_or_default();
        let mut call_stack: Vec<Frame> = vec![Frame {
            node: start,
            children,
            child_idx: 0,
        }];

        while let Some(frame) = call_stack.last_mut() {
            let v = frame.node;
            if frame.child_idx < frame.children.len() {
                let w = frame.children[frame.child_idx];
                frame.child_idx += 1;

                if !index_map.contains_key(w) {
                    // Tree edge: recurse.
                    index_map.insert(w, index_counter);
                    lowlink.insert(w, index_counter);
                    index_counter += 1;
                    tarjan_stack.push(w);
                    on_stack.insert(w);
                    let children_w = adj.get(w).cloned().unwrap_or_default();
                    call_stack.push(Frame {
                        node: w,
                        children: children_w,
                        child_idx: 0,
                    });
                } else if on_stack.contains(w) {
                    // Back edge: update lowlink.
                    let w_idx = *index_map.get(w).unwrap();
                    let v_ll = lowlink.get_mut(v).unwrap();
                    if w_idx < *v_ll {
                        *v_ll = w_idx;
                    }
                }
                // Cross/forward edges (w already fully processed): ignored.
            } else {
                // All children processed: pop this frame.
                let v = frame.node;
                call_stack.pop();

                // Propagate lowlink to parent.
                if let Some(parent_frame) = call_stack.last() {
                    let p = parent_frame.node;
                    let v_ll = *lowlink.get(v).unwrap();
                    let p_ll = lowlink.get_mut(p).unwrap();
                    if v_ll < *p_ll {
                        *p_ll = v_ll;
                    }
                }

                // If v is an SCC root, pop the SCC from tarjan_stack.
                if lowlink[v] == index_map[v] {
                    let mut scc: Vec<String> = Vec::new();
                    loop {
                        let w = tarjan_stack.pop().unwrap();
                        on_stack.remove(w);
                        scc.push(w.to_string());
                        if w == v {
                            break;
                        }
                    }
                    sccs.push(scc);
                }
            }
        }
    }

    debug!("Tarjan found {} SCCs over {} nodes", sccs.len(), all_nodes.len());

    // ------------------------------------------------------------------
    // Step 3 – build scc_id map: node name -> index in sccs.
    // ------------------------------------------------------------------
    let mut scc_id: HashMap<&str, usize> = HashMap::new();
    for (i, scc) in sccs.iter().enumerate() {
        for name in scc {
            scc_id.insert(name.as_str(), i);
        }
    }

    // ------------------------------------------------------------------
    // Step 4 – build condensed DAG: scc_successors[i] = set of successor SCCs.
    // ------------------------------------------------------------------
    let mut scc_successors: Vec<HashSet<usize>> = vec![HashSet::new(); sccs.len()];
    for &node in &all_nodes {
        let my_scc = scc_id[node];
        if let Some(callees) = adj.get(node) {
            for &callee in callees {
                if let Some(&callee_scc) = scc_id.get(callee) {
                    if callee_scc != my_scc {
                        scc_successors[my_scc].insert(callee_scc);
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Step 5 – process SCCs in Tarjan output order (reverse topological =
    // sinks first).  Each SCC is guaranteed to be processed before any SCC
    // that can reach it.
    // ------------------------------------------------------------------
    let mut scc_reachable: Vec<HashSet<String>> = vec![HashSet::new(); sccs.len()];
    let mut scc_depth: Vec<usize> = vec![0usize; sccs.len()];

    for (i, scc) in sccs.iter().enumerate() {
        // Own members.
        let mut reachable: HashSet<String> = scc.iter().cloned().collect();
        let mut max_d: usize = 0;

        for &j in &scc_successors[i] {
            // j was already processed because Tarjan emits sinks first.
            reachable.extend(scc_reachable[j].iter().cloned());
            let d = scc_depth[j] + 1;
            if d > max_d {
                max_d = d;
            }
        }

        scc_reachable[i] = reachable;
        scc_depth[i] = max_d;
    }

    // ------------------------------------------------------------------
    // Step 6 – write results for every function in the original input.
    // ------------------------------------------------------------------
    functions
        .iter()
        .map(|f| {
            let name = f.name.as_str();
            let (reached_set, depth) = match scc_id.get(name) {
                Some(&sid) => (&scc_reachable[sid], scc_depth[sid]),
                None => {
                    // Should not happen: every node was added to all_nodes.
                    debug!("Missing SCC for node {}", name);
                    return FunctionResult {
                        name: f.name.clone(),
                        functions_reached: vec![],
                        function_depth: 0,
                    };
                }
            };
            let mut reached: Vec<String> = reached_set
                .iter()
                .filter(|n| n.as_str() != name)
                .cloned()
                .collect();
            reached.sort_unstable();
            FunctionResult {
                name: f.name.clone(),
                functions_reached: reached,
                function_depth: depth,
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

    fn reached_set(r: &FunctionResult) -> HashSet<&str> {
        r.functions_reached.iter().map(|s| s.as_str()).collect()
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
        // a -> b -> a (cycle); both should be resolvable without panic.
        // With SCC: {a, b} form one SCC; each reaches the other.
        let funcs = vec![mk("a", &["b"]), mk("b", &["a"])];
        let results = compute_reachability(&funcs);
        assert_eq!(results.len(), 2);
        let a = result_for(&results, "a");
        let b = result_for(&results, "b");
        // Both must see each other in their reachable sets.
        assert!(
            reached_set(a).contains("b"),
            "a should reach b; got {:?}",
            a.functions_reached
        );
        assert!(
            reached_set(b).contains("a"),
            "b should reach a; got {:?}",
            b.functions_reached
        );
    }

    #[test]
    fn test_self_loop() {
        // a -> a: trivial SCC containing just a.
        let funcs = vec![mk("a", &["a"])];
        let results = compute_reachability(&funcs);
        assert_eq!(results.len(), 1);
        let a = result_for(&results, "a");
        // Self is excluded from functions_reached.
        assert!(
            a.functions_reached.is_empty(),
            "self loop should produce empty reached set; got {:?}",
            a.functions_reached
        );
    }

    #[test]
    fn test_unknown_callee() {
        // foo calls "external" which has no entry in the function list.
        // external is a leaf SCC; foo's SCC successor is external's SCC.
        // depth[foo] = depth[external] + 1 = 1.
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

    // -----------------------------------------------------------------------
    // New SCC-specific tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_scc_two_node_cycle() {
        // a -> b, b -> a: both should reach each other.
        let funcs = vec![mk("a", &["b"]), mk("b", &["a"])];
        let results = compute_reachability(&funcs);
        let a = result_for(&results, "a");
        let b = result_for(&results, "b");
        assert_eq!(reached_set(a), HashSet::from(["b"]));
        assert_eq!(reached_set(b), HashSet::from(["a"]));
        // Depth: SCC {a,b} has no external successors, so depth = 0.
        assert_eq!(a.function_depth, 0);
        assert_eq!(b.function_depth, 0);
    }

    #[test]
    fn test_scc_three_node_cycle() {
        // a -> b -> c -> a: all three form one SCC and each reaches the others.
        let funcs = vec![mk("a", &["b"]), mk("b", &["c"]), mk("c", &["a"])];
        let results = compute_reachability(&funcs);
        let a = result_for(&results, "a");
        let b = result_for(&results, "b");
        let c = result_for(&results, "c");
        assert_eq!(reached_set(a), HashSet::from(["b", "c"]));
        assert_eq!(reached_set(b), HashSet::from(["a", "c"]));
        assert_eq!(reached_set(c), HashSet::from(["a", "b"]));
        // Pure cycle, no external successors: depth = 0.
        assert_eq!(a.function_depth, 0);
        assert_eq!(b.function_depth, 0);
        assert_eq!(c.function_depth, 0);
    }

    #[test]
    fn test_scc_with_external_callee() {
        // a -> b -> a (cycle SCC), a -> ext (ext not in functions list).
        // Both a and b reach ext; ext is a separate leaf SCC.
        let funcs = vec![mk("a", &["b", "ext"]), mk("b", &["a"])];
        let results = compute_reachability(&funcs);
        let a = result_for(&results, "a");
        let b = result_for(&results, "b");
        // Both should reach ext (and each other).
        assert!(
            reached_set(a).contains("ext"),
            "a should reach ext; got {:?}",
            a.functions_reached
        );
        assert!(
            reached_set(a).contains("b"),
            "a should reach b; got {:?}",
            a.functions_reached
        );
        assert!(
            reached_set(b).contains("ext"),
            "b should reach ext; got {:?}",
            b.functions_reached
        );
        assert!(
            reached_set(b).contains("a"),
            "b should reach a; got {:?}",
            b.functions_reached
        );
        // SCC {a,b} has successor SCC {ext}: depth = depth[ext] + 1 = 1.
        assert_eq!(a.function_depth, 1);
        assert_eq!(b.function_depth, 1);
    }

    #[test]
    fn test_scc_dag_with_cycle() {
        // Graph: a->b, b->c, c->a (SCC1={a,b,c}), a->d, d->e (d,e are DAG sinks).
        // Expected: reachable[a] = {b,c,d,e}, reachable[d] = {e}, reachable[e] = {}
        let funcs = vec![
            mk("a", &["b", "d"]),
            mk("b", &["c"]),
            mk("c", &["a"]),
            mk("d", &["e"]),
            mk("e", &[]),
        ];
        let results = compute_reachability(&funcs);
        let a = result_for(&results, "a");
        let b = result_for(&results, "b");
        let c = result_for(&results, "c");
        let d = result_for(&results, "d");
        let e = result_for(&results, "e");

        assert_eq!(reached_set(a), HashSet::from(["b", "c", "d", "e"]));
        assert_eq!(reached_set(b), HashSet::from(["a", "c", "d", "e"]));
        assert_eq!(reached_set(c), HashSet::from(["a", "b", "d", "e"]));
        assert_eq!(reached_set(d), HashSet::from(["e"]));
        assert!(e.functions_reached.is_empty());

        // Depth: e=0, d=1, SCC{a,b,c}->d->e so depth = 2.
        assert_eq!(e.function_depth, 0);
        assert_eq!(d.function_depth, 1);
        assert_eq!(a.function_depth, 2);
        assert_eq!(b.function_depth, 2);
        assert_eq!(c.function_depth, 2);
    }
}
