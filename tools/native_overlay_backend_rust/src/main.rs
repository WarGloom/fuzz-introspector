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
    target_lang: String,
    #[serde(default)]
    target_coverage_url: String,
    #[serde(default)]
    callsites: Vec<Callsite>,
    #[serde(default)]
    coverage: CoverageInput,
    #[serde(default)]
    functions: BTreeMap<String, FunctionInput>,
}

#[derive(Clone, Debug, Deserialize)]
struct Callsite {
    cov_ct_idx: i64,
    depth: i64,
    dst_function_name: String,
    #[serde(default)]
    #[allow(dead_code)]
    coverage_lookup_name: String,
    #[allow(dead_code)]
    dst_function_source_file: String,
    src_linenumber: i64,
    #[serde(default)]
    cov_link: String,
    #[serde(default)]
    cov_callsite_link: String,
    #[serde(default)]
    python_parent_file_hit: bool,
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
    #[serde(default)]
    kernel_coverage: Vec<KernelModule>,
}

#[derive(Debug, Default, Deserialize)]
struct KernelModule {
    #[serde(rename = "Filename")]
    filename: String,
    #[serde(rename = "Covered")]
    covered: Vec<i64>,
}

#[derive(Debug, Default, Deserialize)]
struct FunctionInput {
    #[serde(default)]
    function_source_file: String,
    #[serde(default)]
    coverage_lookup_name: String,
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

fn callsite_coverage_lookup_name(node: &Callsite) -> &str {
    if node.coverage_lookup_name.is_empty() {
        &node.dst_function_name
    } else {
        &node.coverage_lookup_name
    }
}

fn normalize_kernel_target_file(path: &str) -> &str {
    path.trim_start_matches("../")
}

fn kernel_hitcount(modules: &[KernelModule], target_file: &str, line_number: i64) -> i64 {
    let target_file = normalize_kernel_target_file(target_file);
    if target_file.is_empty() || line_number <= 0 {
        return 0;
    }
    for module in modules {
        if !module.filename.ends_with(target_file) {
            continue;
        }
        for covered_line in &module.covered {
            for offset in 0..10 {
                if *covered_line == line_number + offset {
                    return 100;
                }
            }
        }
    }
    0
}

fn resolve_coverage_lookup_name<'a>(request: &'a OverlayRequest, function_name: &'a str) -> &'a str {
    request
        .functions
        .get(function_name)
        .and_then(|function| {
            if function.coverage_lookup_name.is_empty() {
                None
            } else {
                Some(function.coverage_lookup_name.as_str())
            }
        })
        .unwrap_or(function_name)
}

fn lookup_cov_rows<'a>(request: &'a OverlayRequest, function_name: &'a str) -> Option<&'a Vec<[i64; 2]>> {
    if let Some(rows) = request.coverage.covmap.get(function_name) {
        return Some(rows);
    }
    let lookup_name = resolve_coverage_lookup_name(request, function_name);
    if lookup_name != function_name {
        return request.coverage.covmap.get(lookup_name);
    }
    None
}

fn is_function_hit(request: &OverlayRequest, function_name: &str) -> bool {
    lookup_cov_rows(request, function_name)
        .map(|rows| rows.iter().any(|row| row[1] > 0))
        .unwrap_or(false)
}

fn is_function_line_hit(request: &OverlayRequest, function_name: &str, line_number: i64) -> bool {
    lookup_cov_rows(request, function_name)
        .map(|rows| {
            rows.iter()
                .find(|row| row[0] == line_number)
                .map(|row| row[1] != 0)
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

fn get_hitcount(
    request: &OverlayRequest,
    callstack: &HashMap<i64, String>,
    callstack_source_files: &HashMap<i64, String>,
    node: &Callsite,
    idx: usize,
) -> i64 {
    if idx == 0 {
        if request.target_lang == "c-cpp" && request.coverage.r#type == "kernel" {
            return 100;
        }
        if let Some(rows) = request.coverage.covmap.get(callsite_coverage_lookup_name(node)) {
            return rows.iter().map(|row| row[1]).max().unwrap_or(0);
        }
        return 0;
    }

    let Some(parent_name) = get_parent_name(callstack, node.depth) else {
        return 0;
    };
    if request.target_lang == "c-cpp" && request.coverage.r#type == "kernel" {
        return callstack_source_files
            .get(&(node.depth - 1))
            .map(|parent_source_file| {
                kernel_hitcount(
                    &request.coverage.kernel_coverage,
                    parent_source_file,
                    node.src_linenumber,
                )
            })
            .unwrap_or(0);
    }
    if node.python_parent_file_hit {
        return 200;
    }
    let Some(rows) = request.coverage.covmap.get(parent_name) else {
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
    let mut callstack_source_files: HashMap<i64, String> = HashMap::new();
    let mut overlay_nodes: Vec<OverlayNodeOutput> = Vec::new();
    let mut sorted_callsites = request.callsites.clone();
    sorted_callsites.sort_by_key(|node| node.cov_ct_idx);

    for (idx, node) in sorted_callsites.iter().enumerate() {
        callstack.insert(node.depth, callsite_coverage_lookup_name(node).to_string());
        callstack_source_files.insert(node.depth, node.dst_function_source_file.clone());
        let hit_count = get_hitcount(&request, &callstack, &callstack_source_files, node, idx);
        overlay_nodes.push(OverlayNodeOutput {
            cov_ct_idx: node.cov_ct_idx,
            cov_hitcount: hit_count,
            cov_color: color_for_hitcount(hit_count).to_string(),
            cov_link: node.cov_link.clone(),
            cov_callsite_link: node.cov_callsite_link.clone(),
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

    let mut prev_end: i64 = -1;
    for idx in 0..overlay_nodes.len() {
        let mut prev_depth_leq = false;
        if idx > 0 {
            prev_depth_leq = sorted_callsites[idx - 1].depth <= sorted_callsites[idx].depth;
        }
        if overlay_nodes[idx].cov_hitcount == 0 && (prev_depth_leq || (idx as i64) < prev_end) {
            overlay_nodes[idx].cov_forward_reds = 0;
            overlay_nodes[idx].cov_largest_blocked_func = "none".to_string();
            continue;
        }

        let mut forward_reds = 0i64;
        let mut largest_name = String::new();
        let mut largest_complexity = 0i64;
        let mut look_ahead = idx + 1;
        while look_ahead < overlay_nodes.len() {
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
            look_ahead += 1;
        }
        prev_end = (look_ahead as i64) - 1;
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
                    let is_hit = is_function_hit(&request, func_name);
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
            if request.coverage.r#type == "file" {
                if is_side_hit(
                    &request.coverage,
                    &function_data.function_source_file,
                    &function_name,
                    blocked_line,
                ) {
                    continue;
                }
            } else if request.target_lang == "c-cpp" && request.coverage.r#type == "kernel" {
                if kernel_hitcount(
                    &request.coverage.kernel_coverage,
                    &function_data.function_source_file,
                    blocked_line,
                ) > 0
                {
                    continue;
                }
            } else if is_function_line_hit(&request, &function_name, blocked_line) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn overlay_request_with_coverage(coverage: CoverageInput) -> OverlayRequest {
        OverlayRequest {
            output_dir: String::new(),
            target_lang: String::new(),
            target_coverage_url: String::new(),
            callsites: Vec::new(),
            coverage,
            functions: BTreeMap::new(),
        }
    }

    #[test]
    fn get_hitcount_uses_python_parent_file_hit_override() {
        let coverage = CoverageInput {
            r#type: "file".to_string(),
            covmap: BTreeMap::from([("pkg.entry".to_string(), vec![[1, 5]])]),
            file_map: BTreeMap::new(),
            branch_cov_map: BTreeMap::new(),
            kernel_coverage: Vec::new(),
        };
        let request = overlay_request_with_coverage(coverage);
        let callstack = HashMap::from([(0, "pkg.entry".to_string())]);
        let callstack_source_files = HashMap::from([(0, "pkg.py".to_string())]);
        let node = Callsite {
            cov_ct_idx: 1,
            depth: 1,
            dst_function_name: "pkg.leaf".to_string(),
            coverage_lookup_name: "pkg.leaf".to_string(),
            dst_function_source_file: "pkg.py".to_string(),
            src_linenumber: 12,
            cov_link: String::new(),
            cov_callsite_link: String::new(),
            python_parent_file_hit: true,
        };

        assert_eq!(
            get_hitcount(&request, &callstack, &callstack_source_files, &node, 1),
            200
        );
    }

    #[test]
    fn get_hitcount_uses_parent_covmap_without_python_override() {
        let coverage = CoverageInput {
            r#type: "function".to_string(),
            covmap: BTreeMap::from([("entry".to_string(), vec![[7, 11]])]),
            file_map: BTreeMap::new(),
            branch_cov_map: BTreeMap::new(),
            kernel_coverage: Vec::new(),
        };
        let request = overlay_request_with_coverage(coverage);
        let callstack = HashMap::from([(0, "entry".to_string())]);
        let callstack_source_files = HashMap::from([(0, "a.c".to_string())]);
        let node = Callsite {
            cov_ct_idx: 1,
            depth: 1,
            dst_function_name: "leaf".to_string(),
            coverage_lookup_name: "leaf".to_string(),
            dst_function_source_file: "a.c".to_string(),
            src_linenumber: 7,
            cov_link: String::new(),
            cov_callsite_link: String::new(),
            python_parent_file_hit: false,
        };

        assert_eq!(
            get_hitcount(&request, &callstack, &callstack_source_files, &node, 1),
            11
        );
    }

    #[test]
    fn get_hitcount_uses_coverage_lookup_name_for_root_and_parent() {
        let request = OverlayRequest {
            output_dir: String::new(),
            target_lang: "c-cpp".to_string(),
            target_coverage_url: String::new(),
            callsites: Vec::new(),
            coverage: CoverageInput {
                r#type: "function".to_string(),
                covmap: BTreeMap::from([("entry()".to_string(), vec![[1, 5], [7, 11]])]),
                file_map: BTreeMap::new(),
                branch_cov_map: BTreeMap::new(),
                kernel_coverage: Vec::new(),
            },
            functions: BTreeMap::new(),
        };
        let root = Callsite {
            cov_ct_idx: 0,
            depth: 0,
            dst_function_name: "_Z5entryv".to_string(),
            coverage_lookup_name: "entry()".to_string(),
            dst_function_source_file: "a.cc".to_string(),
            src_linenumber: 1,
            cov_link: String::new(),
            cov_callsite_link: String::new(),
            python_parent_file_hit: false,
        };
        let child = Callsite {
            cov_ct_idx: 1,
            depth: 1,
            dst_function_name: "_Z4leafv".to_string(),
            coverage_lookup_name: "leaf()".to_string(),
            dst_function_source_file: "a.cc".to_string(),
            src_linenumber: 7,
            cov_link: String::new(),
            cov_callsite_link: String::new(),
            python_parent_file_hit: false,
        };
        let root_stack = HashMap::from([(0, "entry()".to_string())]);
        let source_files = HashMap::from([(0, "a.cc".to_string())]);

        assert_eq!(get_hitcount(&request, &HashMap::new(), &HashMap::new(), &root, 0), 11);
        assert_eq!(get_hitcount(&request, &root_stack, &source_files, &child, 1), 11);
    }

    #[test]
    fn get_hitcount_uses_kernel_semantics_for_cpp() {
        let request = OverlayRequest {
            output_dir: String::new(),
            target_lang: "c-cpp".to_string(),
            target_coverage_url: String::new(),
            callsites: Vec::new(),
            coverage: CoverageInput {
                r#type: "kernel".to_string(),
                covmap: BTreeMap::new(),
                file_map: BTreeMap::new(),
                branch_cov_map: BTreeMap::new(),
                kernel_coverage: vec![KernelModule {
                    filename: "/tmp/build/src/foo.c".to_string(),
                    covered: vec![18],
                }],
            },
            functions: BTreeMap::new(),
        };
        let root = Callsite {
            cov_ct_idx: 0,
            depth: 0,
            dst_function_name: "entry".to_string(),
            coverage_lookup_name: "entry".to_string(),
            dst_function_source_file: "../src/foo.c".to_string(),
            src_linenumber: 1,
            cov_link: String::new(),
            cov_callsite_link: String::new(),
            python_parent_file_hit: false,
        };
        let child = Callsite {
            cov_ct_idx: 1,
            depth: 1,
            dst_function_name: "leaf".to_string(),
            coverage_lookup_name: "leaf".to_string(),
            dst_function_source_file: "../src/bar.c".to_string(),
            src_linenumber: 10,
            cov_link: String::new(),
            cov_callsite_link: String::new(),
            python_parent_file_hit: false,
        };
        let callstack = HashMap::from([(0, "entry".to_string())]);
        let source_files = HashMap::from([(0, "../src/foo.c".to_string())]);

        assert_eq!(get_hitcount(&request, &HashMap::new(), &HashMap::new(), &root, 0), 100);
        assert_eq!(get_hitcount(&request, &callstack, &source_files, &child, 1), 100);
    }

    #[test]
    fn function_hit_helpers_resolve_demangled_lookup_names() {
        let request = OverlayRequest {
            output_dir: String::new(),
            target_lang: "c-cpp".to_string(),
            target_coverage_url: String::new(),
            callsites: Vec::new(),
            coverage: CoverageInput {
                r#type: "function".to_string(),
                covmap: BTreeMap::from([("foo()".to_string(), vec![[11, 3]])]),
                file_map: BTreeMap::new(),
                branch_cov_map: BTreeMap::new(),
                kernel_coverage: Vec::new(),
            },
            functions: BTreeMap::from([(
                "_Z3foov".to_string(),
                FunctionInput {
                    function_source_file: "a.cc".to_string(),
                    coverage_lookup_name: "foo()".to_string(),
                    total_cyclomatic_complexity: 7,
                    branch_profiles: BTreeMap::new(),
                },
            )]),
        };

        assert!(is_function_hit(&request, "_Z3foov"));
        assert!(is_function_line_hit(&request, "_Z3foov", 11));
        assert!(!is_function_line_hit(&request, "_Z3foov", 12));
    }

    #[test]
    fn kernel_and_file_branch_blocker_checks_match_coverage_type() {
        let file_coverage = CoverageInput {
            r#type: "file".to_string(),
            covmap: BTreeMap::from([("foo".to_string(), vec![[11, 0]])]),
            file_map: BTreeMap::from([("a.py".to_string(), vec![[11, 1]])]),
            branch_cov_map: BTreeMap::new(),
            kernel_coverage: Vec::new(),
        };
        assert!(is_side_hit(&file_coverage, "a.py", "foo", 11));

        let kernel_modules = vec![KernelModule {
            filename: "/tmp/build/src/foo.c".to_string(),
            covered: vec![15],
        }];
        assert_eq!(kernel_hitcount(&kernel_modules, "../src/foo.c", 10), 100);
        assert_eq!(kernel_hitcount(&kernel_modules, "../src/foo.c", 16), 0);
    }
}
