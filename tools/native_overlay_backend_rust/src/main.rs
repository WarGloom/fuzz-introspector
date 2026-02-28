use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const SCHEMA_VERSION: i64 = 1;

#[derive(Debug, Deserialize)]
struct OverlayRequest {
    #[serde(default)]
    output_dir: String,
    #[serde(default)]
    target_coverage_url: String,
    #[serde(default)]
    callsites: Vec<Callsite>,
    #[serde(default)]
    coverage: CoverageInput,
    #[serde(default)]
    functions: BTreeMap<String, FunctionInput>,
}

#[derive(Debug, Deserialize)]
struct Callsite {
    cov_ct_idx: i64,
    depth: i64,
    dst_function_name: String,
    #[allow(dead_code)]
    dst_function_source_file: String,
    src_linenumber: i64,
}

#[derive(Debug, Default, Deserialize)]
struct CoverageInput {
    #[serde(default)]
    #[allow(dead_code)]
    r#type: String,
    #[serde(default)]
    covmap: BTreeMap<String, Vec<[i64; 2]>>,
    #[serde(default)]
    file_map: BTreeMap<String, Vec<[i64; 2]>>,
    #[serde(default)]
    branch_cov_map: BTreeMap<String, Vec<i64>>,
}

#[derive(Debug, Default, Deserialize)]
struct FunctionInput {
    #[serde(default)]
    function_source_file: String,
    #[serde(default)]
    total_cyclomatic_complexity: i64,
    #[serde(default)]
    branch_profiles: BTreeMap<String, BranchInput>,
}

#[derive(Debug, Default, Deserialize)]
struct BranchInput {
    #[serde(default)]
    sides: Vec<BranchSideInput>,
}

#[derive(Debug, Default, Deserialize)]
struct BranchSideInput {
    #[serde(default)]
    pos: String,
    #[serde(default)]
    funcs: Vec<String>,
}

#[derive(Debug, Serialize)]
struct OverlayNodeOutput {
    cov_ct_idx: i64,
    cov_hitcount: i64,
    cov_color: String,
    cov_link: String,
    cov_callsite_link: String,
    cov_forward_reds: i64,
    cov_largest_blocked_func: String,
}

#[derive(Debug, Serialize)]
struct BranchComplexityOutput {
    function_name: String,
    branch: String,
    side_idx: i64,
    unique_not_covered_complexity: i64,
    unique_reachable_complexity: i64,
    reachable_complexity: i64,
    not_covered_complexity: i64,
}

#[derive(Debug, Serialize)]
struct BranchBlockerOutput {
    blocked_side: String,
    blocked_unique_not_covered_complexity: i64,
    blocked_unique_reachable_complexity: i64,
    blocked_unique_functions: Vec<String>,
    blocked_not_covered_complexity: i64,
    blocked_reachable_complexity: i64,
    sides_hitcount_diff: i64,
    source_file: String,
    branch_line_number: String,
    blocked_side_line_numder: String,
    function_name: String,
}

#[derive(Debug, Serialize)]
struct OverlayResponse {
    schema_version: i64,
    status: String,
    counters: BTreeMap<String, i64>,
    artifacts: BTreeMap<String, String>,
    timings: BTreeMap<String, i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason_code: Option<String>,
}

fn color_for_hitcount(hit_count: i64) -> &'static str {
    if hit_count <= 0 {
        return "red";
    }
    if hit_count < 10 {
        return "gold";
    }
    if hit_count < 30 {
        return "yellow";
    }
    if hit_count < 50 {
        return "greenyellow";
    }
    "lawngreen"
}

fn get_parent_name(stack: &HashMap<i64, String>, depth: i64) -> Option<&str> {
    stack.get(&(depth - 1)).map(|name| name.as_str())
}

fn get_hitcount(coverage: &CoverageInput, callstack: &HashMap<i64, String>, node: &Callsite, idx: usize) -> i64 {
    if idx == 0 {
        if let Some(rows) = coverage.covmap.get(&node.dst_function_name) {
            return rows.iter().map(|row| row[1]).max().unwrap_or(0);
        }
        return 0;
    }

    let Some(parent_name) = get_parent_name(callstack, node.depth) else {
        return 0;
    };
    let Some(rows) = coverage.covmap.get(parent_name) else {
        return 0;
    };
    for row in rows {
        if row[0] == node.src_linenumber && row[1] > 0 {
            return row[1];
        }
    }
    0
}

fn split_branch_key(branch_key: &str) -> Option<(String, String, String)> {
    let (function_name, rest) = branch_key.rsplit_once(':')?;
    let (line, col) = rest.split_once(',')?;
    Some((function_name.to_string(), line.to_string(), col.to_string()))
}

fn basename(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|v| v.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string())
}

fn parse_side_line(pos: &str) -> Option<i64> {
    let (_, rest) = pos.split_once(':')?;
    let (line, _) = rest.split_once(',')?;
    line.parse::<i64>().ok()
}

fn is_side_hit(coverage: &CoverageInput, source_file: &str, function_name: &str, side_line: i64) -> bool {
    if let Some(file_rows) = coverage.file_map.get(source_file) {
        return file_rows.iter().any(|row| row[0] == side_line && row[1] > 0);
    }
    if let Some(func_rows) = coverage.covmap.get(function_name) {
        return func_rows.iter().any(|row| row[0] == side_line && row[1] > 0);
    }
    false
}

fn write_json_file<T: Serialize>(path: &Path, payload: &T) -> Result<(), String> {
    let file = File::create(path).map_err(|err| format!("failed creating {}: {err}", path.display()))?;
    serde_json::to_writer(file, payload)
        .map_err(|err| format!("failed writing {}: {err}", path.display()))
}

fn main() {
    if let Err(err) = run() {
        let mut counters = BTreeMap::new();
        counters.insert("overlay_nodes".to_string(), 0);
        counters.insert("branch_complexities".to_string(), 0);
        counters.insert("branch_blockers".to_string(), 0);

        let response = OverlayResponse {
            schema_version: SCHEMA_VERSION,
            status: "error".to_string(),
            counters,
            artifacts: BTreeMap::new(),
            timings: BTreeMap::new(),
            reason_code: Some(err),
        };
        let mut stdout = io::stdout();
        let _ = serde_json::to_writer(&mut stdout, &response);
        let _ = stdout.write_all(b"\n");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|err| format!("failed reading stdin: {err}"))?;
    let request: OverlayRequest =
        serde_json::from_str(&input).map_err(|err| format!("invalid request json: {err}"))?;

    let output_dir = if request.output_dir.is_empty() {
        PathBuf::from(".")
    } else {
        PathBuf::from(&request.output_dir)
    };
    fs::create_dir_all(&output_dir)
        .map_err(|err| format!("failed creating output_dir {}: {err}", output_dir.display()))?;

    let mut callstack: HashMap<i64, String> = HashMap::new();
    let mut overlay_nodes: Vec<OverlayNodeOutput> = Vec::new();
    let mut sorted_callsites = request.callsites;
    sorted_callsites.sort_by_key(|node| node.cov_ct_idx);

    for (idx, node) in sorted_callsites.iter().enumerate() {
        callstack.insert(node.depth, node.dst_function_name.clone());
        let hit_count = get_hitcount(&request.coverage, &callstack, node, idx);
        overlay_nodes.push(OverlayNodeOutput {
            cov_ct_idx: node.cov_ct_idx,
            cov_hitcount: hit_count,
            cov_color: color_for_hitcount(hit_count).to_string(),
            cov_link: "#".to_string(),
            cov_callsite_link: "#".to_string(),
            cov_forward_reds: 0,
            cov_largest_blocked_func: "".to_string(),
        });
    }

    if overlay_nodes.len() > 1 {
        if overlay_nodes.iter().skip(1).any(|node| node.cov_hitcount > 0) {
            if let Some(first) = overlay_nodes.get_mut(0) {
                first.cov_hitcount = 200;
                first.cov_color = color_for_hitcount(200).to_string();
            }
        }
    }

    for idx in 0..overlay_nodes.len() {
        let mut forward_reds = 0i64;
        let mut largest_name = String::new();
        let mut largest_complexity = 0i64;
        for look_ahead in (idx + 1)..overlay_nodes.len() {
            if overlay_nodes[look_ahead].cov_hitcount != 0 {
                break;
            }
            let look_name = &sorted_callsites[look_ahead].dst_function_name;
            if let Some(function_data) = request.functions.get(look_name) {
                if function_data.total_cyclomatic_complexity > largest_complexity {
                    largest_complexity = function_data.total_cyclomatic_complexity;
                    largest_name = look_name.to_string();
                }
            }
            forward_reds += 1;
        }
        overlay_nodes[idx].cov_forward_reds = forward_reds;
        overlay_nodes[idx].cov_largest_blocked_func = largest_name;
    }

    let mut branch_complexities: Vec<BranchComplexityOutput> = Vec::new();
    for (function_name, function_data) in &request.functions {
        for (branch_name, branch_data) in &function_data.branch_profiles {
            for (side_idx, side) in branch_data.sides.iter().enumerate() {
                let mut other_side_funcs: BTreeSet<String> = BTreeSet::new();
                for (iter_idx, iter_side) in branch_data.sides.iter().enumerate() {
                    if iter_idx == side_idx {
                        continue;
                    }
                    for func_name in &iter_side.funcs {
                        other_side_funcs.insert(func_name.clone());
                    }
                }

                let mut unique_funcs: BTreeSet<String> = BTreeSet::new();
                for func_name in &side.funcs {
                    if !other_side_funcs.contains(func_name) {
                        unique_funcs.insert(func_name.clone());
                    }
                }

                let mut unique_not_covered = 0i64;
                let mut unique_reachable = 0i64;
                let mut reachable = 0i64;
                let mut not_covered = 0i64;
                for func_name in &side.funcs {
                    let complexity = request
                        .functions
                        .get(func_name)
                        .map(|f| f.total_cyclomatic_complexity)
                        .unwrap_or(0);
                    reachable += complexity;
                    if unique_funcs.contains(func_name) {
                        unique_reachable += complexity;
                    }
                    let is_hit = request
                        .coverage
                        .covmap
                        .get(func_name)
                        .map(|rows| rows.iter().any(|row| row[1] > 0))
                        .unwrap_or(false);
                    if !is_hit {
                        not_covered += complexity;
                        if unique_funcs.contains(func_name) {
                            unique_not_covered += complexity;
                        }
                    }
                }

                branch_complexities.push(BranchComplexityOutput {
                    function_name: function_name.clone(),
                    branch: branch_name.clone(),
                    side_idx: side_idx as i64,
                    unique_not_covered_complexity: unique_not_covered,
                    unique_reachable_complexity: unique_reachable,
                    reachable_complexity: reachable,
                    not_covered_complexity: not_covered,
                });
            }
        }
    }
    branch_complexities.sort_by(|a, b| {
        (&a.function_name, &a.branch, a.side_idx).cmp(&(&b.function_name, &b.branch, b.side_idx))
    });

    let mut branch_complexity_lookup: BTreeMap<(String, String, i64), &BranchComplexityOutput> = BTreeMap::new();
    for item in &branch_complexities {
        branch_complexity_lookup.insert(
            (item.function_name.clone(), item.branch.clone(), item.side_idx),
            item,
        );
    }

    let mut branch_blockers: Vec<BranchBlockerOutput> = Vec::new();
    for (branch_string, side_hits_raw) in &request.coverage.branch_cov_map {
        let mut side_hits = side_hits_raw.clone();
        let mut branch_hitcount = -1i64;
        if side_hits.len() > 2 {
            branch_hitcount = *side_hits.iter().take(2).max().unwrap_or(&-1);
            side_hits = side_hits[2..].to_vec();
        }

        let Some((function_name, line_number, column_number)) = split_branch_key(branch_string) else {
            continue;
        };
        let Some(function_data) = request.functions.get(&function_name) else {
            continue;
        };
        let llvm_branch = format!(
            "{}:{},{}",
            basename(&function_data.function_source_file),
            line_number,
            column_number
        );
        let Some(branch_data) = function_data.branch_profiles.get(&llvm_branch) else {
            continue;
        };
        if side_hits.len() != branch_data.sides.len() {
            continue;
        }

        let mut taken = false;
        let mut not_taken_indices: Vec<usize> = Vec::new();
        for (idx, hit) in side_hits.iter().enumerate() {
            if *hit == 0 {
                not_taken_indices.push(idx);
            } else {
                taken = true;
            }
        }
        if !taken || not_taken_indices.is_empty() {
            continue;
        }

        for blocked_idx in not_taken_indices {
            let Some(side) = branch_data.sides.get(blocked_idx) else {
                continue;
            };
            let Some(blocked_line) = parse_side_line(&side.pos) else {
                continue;
            };
            let branch_line = line_number.parse::<i64>().unwrap_or(0);
            if branch_line > blocked_line {
                continue;
            }
            if is_side_hit(
                &request.coverage,
                &function_data.function_source_file,
                &function_name,
                blocked_line,
            ) {
                continue;
            }

            let key = (function_name.clone(), llvm_branch.clone(), blocked_idx as i64);
            let Some(complexity) = branch_complexity_lookup.get(&key) else {
                continue;
            };

            let mut other_side_funcs: BTreeSet<String> = BTreeSet::new();
            for (iter_idx, iter_side) in branch_data.sides.iter().enumerate() {
                if iter_idx == blocked_idx {
                    continue;
                }
                for func_name in &iter_side.funcs {
                    other_side_funcs.insert(func_name.clone());
                }
            }

            let unique_funcs: Vec<String> = side
                .funcs
                .iter()
                .filter(|func_name| !other_side_funcs.contains(*func_name))
                .map(|func_name| func_name.to_string())
                .collect();

            let mut max_hit = branch_hitcount;
            for hit in &side_hits {
                if *hit > max_hit {
                    max_hit = *hit;
                }
            }

            branch_blockers.push(BranchBlockerOutput {
                blocked_side: blocked_idx.to_string(),
                blocked_unique_not_covered_complexity: complexity.unique_not_covered_complexity,
                blocked_unique_reachable_complexity: complexity.unique_reachable_complexity,
                blocked_unique_functions: unique_funcs,
                blocked_not_covered_complexity: complexity.not_covered_complexity,
                blocked_reachable_complexity: complexity.reachable_complexity,
                sides_hitcount_diff: max_hit,
                source_file: function_data.function_source_file.clone(),
                branch_line_number: line_number.clone(),
                blocked_side_line_numder: blocked_line.to_string(),
                function_name: function_name.clone(),
            });
        }
    }
    branch_blockers.sort_by(|a, b| {
        (
            b.blocked_unique_not_covered_complexity,
            b.blocked_unique_reachable_complexity,
            b.blocked_not_covered_complexity,
            b.blocked_reachable_complexity,
        )
            .cmp(&(
                a.blocked_unique_not_covered_complexity,
                a.blocked_unique_reachable_complexity,
                a.blocked_not_covered_complexity,
                a.blocked_reachable_complexity,
            ))
    });

    let overlay_nodes_path = output_dir.join("overlay_nodes.json");
    let branch_complexities_path = output_dir.join("branch_complexities.json");
    let branch_blockers_path = output_dir.join("branch_blockers.json");
    write_json_file(&overlay_nodes_path, &overlay_nodes)?;
    write_json_file(&branch_complexities_path, &branch_complexities)?;
    write_json_file(&branch_blockers_path, &branch_blockers)?;

    let mut counters = BTreeMap::new();
    counters.insert("callsites".to_string(), overlay_nodes.len() as i64);
    counters.insert("branch_complexities".to_string(), branch_complexities.len() as i64);
    counters.insert("branch_blockers".to_string(), branch_blockers.len() as i64);

    let mut artifacts = BTreeMap::new();
    artifacts.insert(
        "overlay_nodes".to_string(),
        overlay_nodes_path.to_string_lossy().to_string(),
    );
    artifacts.insert(
        "branch_complexities".to_string(),
        branch_complexities_path.to_string_lossy().to_string(),
    );
    artifacts.insert(
        "branch_blockers".to_string(),
        branch_blockers_path.to_string_lossy().to_string(),
    );

    let mut timings = BTreeMap::new();
    timings.insert("total_ms".to_string(), 0);

    let response = OverlayResponse {
        schema_version: SCHEMA_VERSION,
        status: "success".to_string(),
        counters,
        artifacts,
        timings,
        reason_code: None,
    };

    let mut stdout = io::stdout();
    serde_json::to_writer(&mut stdout, &response)
        .map_err(|err| format!("failed writing response: {err}"))?;
    stdout
        .write_all(b"\n")
        .map_err(|err| format!("failed writing newline: {err}"))?;
    let _ = &request.target_coverage_url;
    Ok(())
}
