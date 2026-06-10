use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

const DEFAULT_SHARD_SIZE: usize = 5000;

#[derive(Debug)]
struct AppError {
    reason_code: &'static str,
    message: String,
}

impl AppError {
    fn new(reason_code: &'static str, message: impl Into<String>) -> Self {
        Self {
            reason_code,
            message: message.into(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct Request {
    schema_version: i64,
    #[serde(default)]
    stage: Option<String>,
    #[serde(default)]
    debug_types_paths: Vec<String>,
    #[serde(default)]
    debug_functions_paths: Vec<String>,
    #[serde(default)]
    debug_types: Vec<JsonValue>,
    #[serde(default)]
    debug_functions: Vec<JsonValue>,
    #[serde(default)]
    output_dir: Option<String>,
    #[serde(default)]
    shard_size: Option<usize>,
    #[serde(default = "default_dump_files")]
    dump_files: bool,
    #[serde(default)]
    out_dir: Option<String>,
    #[serde(default)]
    introspection_functions: Vec<JsonValue>,
    #[serde(default)]
    project_language: Option<String>,
    #[serde(default)]
    all_files_in_project: Vec<JsonValue>,
}

fn default_dump_files() -> bool {
    true
}

#[derive(Debug, Default, Serialize)]
struct Counters {
    parsed_types: usize,
    parsed_functions: usize,
    deduped_functions: usize,
    written_records: usize,
    updated_functions: usize,
    correlated_functions: usize,
    shards: usize,
}

#[derive(Debug, Default, Serialize)]
struct Artifacts {
    correlated_shards: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    all_friendly_debug_types: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    function_updates: Vec<JsonValue>,
}

#[derive(Debug, Default, Serialize)]
struct Timings {
    parse_ms: u64,
    dedupe_ms: u64,
    correlate_ms: u64,
    write_ms: u64,
    total_ms: u64,
}

#[derive(Debug, Serialize)]
struct Response {
    schema_version: i64,
    status: &'static str,
    counters: Counters,
    artifacts: Artifacts,
    timings: Timings,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason_code: Option<String>,
}

#[derive(Clone)]
struct TypeEntry {
    addr: i128,
    tag: String,
    name: String,
    base_type_addr: i128,
    base_type_string: String,
    const_size: i64,
    scope: i128,
    enum_elems: JsonValue,
    raw_debug_info: JsonValue,
}

#[derive(Default)]
struct TypeIndex {
    entries: HashMap<i128, TypeEntry>,
    addr_order: Vec<i128>,
}

#[derive(Clone)]
struct FunctionEntry {
    original_row_idx: usize,
    file_location: String,
    type_arguments: Vec<i128>,
}

#[derive(Clone, Serialize)]
struct FunctionSignatureElems {
    return_type: JsonValue,
    params: Vec<Vec<String>>,
}

#[derive(Clone, Serialize)]
struct SourceLocation {
    source_file: String,
    source_line: String,
}

#[derive(Clone, Serialize)]
struct CorrelatedRecord {
    row_idx: usize,
    func_signature_elems: FunctionSignatureElems,
    source: SourceLocation,
}

#[derive(Default)]
struct CorrelationWriteResult {
    correlated_shards: Vec<String>,
    written_records: usize,
    correlate_ms: u64,
    write_ms: u64,
}

struct CachedCorrelationResult {
    func_signature_elems: FunctionSignatureElems,
    source: SourceLocation,
}

fn to_ms(duration: std::time::Duration) -> u64 {
    duration.as_millis() as u64
}

fn extract_schema_version(raw_payload: &str) -> i64 {
    match serde_json::from_str::<JsonValue>(raw_payload) {
        Ok(payload) => payload
            .get("schema_version")
            .and_then(parse_i64)
            .unwrap_or(0),
        Err(_) => 0,
    }
}

fn parse_i128(value: &JsonValue) -> Option<i128> {
    if let Some(v) = value.as_i64() {
        return Some(v as i128);
    }
    if let Some(v) = value.as_u64() {
        return Some(v as i128);
    }
    value
        .as_str()
        .and_then(|text| text.trim().parse::<i128>().ok())
}

fn parse_i64(value: &JsonValue) -> Option<i64> {
    if let Some(v) = value.as_i64() {
        return Some(v);
    }
    if let Some(v) = value.as_u64() {
        return i64::try_from(v).ok();
    }
    value
        .as_str()
        .and_then(|text| text.trim().parse::<i64>().ok())
}

fn normalize_records(value: JsonValue, out: &mut Vec<JsonValue>) {
    match value {
        JsonValue::Null => {}
        JsonValue::Array(items) => out.extend(items),
        JsonValue::Object(mut object) => {
            if let Some(items_value) = object.remove("items") {
                if let JsonValue::Array(items) = items_value {
                    out.extend(items);
                    return;
                }
            }
            out.push(JsonValue::Object(object));
        }
        _ => {}
    }
}

fn parse_records_from_file(path: &str) -> Result<Vec<JsonValue>, AppError> {
    let content = fs::read_to_string(path)
        .map_err(|err| AppError::new("io_error", format!("failed reading {path}: {err}")))?;
    if content.trim().is_empty() {
        return Ok(Vec::new());
    }

    // Fast path for JSON/NDJSON input shards emitted by Python.
    let mut ndjson_records: Vec<JsonValue> = Vec::new();
    let mut ndjson_mode = false;
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<JsonValue>(line) {
            Ok(value) => {
                ndjson_mode = true;
                normalize_records(value, &mut ndjson_records);
            }
            Err(_) => {
                ndjson_mode = false;
                ndjson_records.clear();
                break;
            }
        }
    }
    if ndjson_mode {
        return Ok(ndjson_records);
    }

    // Fallback for full JSON/YAML payloads (reuse already-read string; no second file open).
    let parsed: JsonValue = serde_yaml::from_str(&content).map_err(|err| {
        AppError::new(
            "parse_error",
            format!("failed parsing YAML/JSON in {path}: {err}"),
        )
    })?;

    let mut records: Vec<JsonValue> = Vec::new();
    normalize_records(parsed, &mut records);
    Ok(records)
}

fn load_records_from_paths(paths: &[String]) -> Result<Vec<JsonValue>, AppError> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }

    // Parse files sequentially to prevent massive memory spikes and thread starvation
    // which occurs when concurrently parsing dozens of huge YAML files.
    let per_file: Vec<Result<Vec<JsonValue>, AppError>> = paths
        .iter()
        .map(|path| parse_records_from_file(path))
        .collect();

    let mut merged: Vec<JsonValue> = Vec::new();
    for result in per_file {
        merged.extend(result?);
    }
    Ok(merged)
}

fn parse_type_entry(record: &JsonValue) -> Option<TypeEntry> {
    let mut raw_debug_info = record.clone();
    let object = raw_debug_info.as_object_mut()?;

    let mut name = object
        .get("name")
        .and_then(JsonValue::as_str)
        .unwrap_or("")
        .to_string();
    if name == "_Bool" {
        name = "bool".to_string();
        object.insert("name".to_string(), JsonValue::String(name.clone()));
    }

    let addr = parse_i128(object.get("addr")?)?;

    let tag = object
        .get("tag")
        .and_then(JsonValue::as_str)
        .unwrap_or("")
        .to_string();
    let base_type_addr = object
        .get("base_type_addr")
        .and_then(parse_i128)
        .unwrap_or(0);
    let base_type_string = object
        .get("base_type_string")
        .and_then(JsonValue::as_str)
        .unwrap_or("")
        .to_string();
    let const_size = object
        .get("const_size")
        .and_then(parse_i64)
        .unwrap_or(0);
    let scope = object.get("scope").and_then(parse_i128).unwrap_or(0);
    let enum_elems = object
        .get("enum_elems")
        .cloned()
        .unwrap_or_else(|| JsonValue::Array(Vec::new()));

    Some(TypeEntry {
        addr,
        tag,
        name,
        base_type_addr,
        base_type_string,
        const_size,
        scope,
        enum_elems,
        raw_debug_info,
    })
}

fn parse_function_entry(record: &JsonValue, original_row_idx: usize) -> Option<FunctionEntry> {
    let object = record.as_object()?;
    let file_location = object
        .get("file_location")
        .and_then(JsonValue::as_str)
        .unwrap_or("")
        .to_string();

    let type_arguments = object
        .get("type_arguments")
        .and_then(JsonValue::as_array)
        .map(|args| {
            args.iter()
                .filter_map(parse_i128)
                .collect::<Vec<i128>>()
        })
        .unwrap_or_default();

    Some(FunctionEntry {
        original_row_idx,
        file_location,
        type_arguments,
    })
}

fn build_type_index(records: &[JsonValue]) -> TypeIndex {
    // Parse all records in parallel — order is preserved by rayon.
    let parsed: Vec<Option<TypeEntry>> =
        records.par_iter().map(|r| parse_type_entry(r)).collect();

    // Dedup sequentially to preserve insertion-order addr_order.
    let mut index = TypeIndex::default();
    for type_entry in parsed.into_iter().flatten() {
        if !index.entries.contains_key(&type_entry.addr) {
            index.addr_order.push(type_entry.addr);
        }
        index.entries.insert(type_entry.addr, type_entry);
    }
    index
}

fn build_correlation_plan(functions: &[FunctionEntry]) -> (Vec<usize>, Vec<usize>) {
    let mut unique_row_indices: Vec<usize> = Vec::new();
    let mut row_to_unique_idx: Vec<usize> = Vec::with_capacity(functions.len());
    let mut key_to_unique_idx: HashMap<(&str, &[i128]), usize> = HashMap::with_capacity(functions.len());

    for (row_idx, function) in functions.iter().enumerate() {
        let key = (
            function.file_location.as_str(),
            function.type_arguments.as_slice(),
        );
        let unique_idx = if let Some(existing_idx) = key_to_unique_idx.get(&key) {
            *existing_idx
        } else {
            let next_idx = unique_row_indices.len();
            unique_row_indices.push(row_idx);
            key_to_unique_idx.insert(key, next_idx);
            next_idx
        };
        row_to_unique_idx.push(unique_idx);
    }

    (unique_row_indices, row_to_unique_idx)
}

fn extract_func_sig_friendly_type_tags(target_type: i128, type_map: &HashMap<i128, TypeEntry>) -> Vec<String> {
    if target_type == 0 {
        return vec!["void".to_string()];
    }

    let mut tags: Vec<String> = Vec::new();
    let mut type_to_query = target_type;
    let mut visited: HashSet<i128> = HashSet::new();

    loop {
        if visited.contains(&type_to_query) {
            tags.push("Infinite loop".to_string());
            break;
        }

        let Some(target) = type_map.get(&type_to_query) else {
            tags.push("N/A".to_string());
            break;
        };

        tags.push(target.tag.clone());
        if target.tag.contains("array") {
            tags.push(format!("ARRAY-SIZE: {}", target.const_size));
        }

        if !target.name.is_empty() {
            tags.push(target.name.clone());
            break;
        }

        if !target.base_type_string.is_empty() {
            tags.push(target.base_type_string.clone());
            break;
        }

        visited.insert(type_to_query);
        type_to_query = target.base_type_addr;

        if type_to_query == 0 {
            tags.push("void".to_string());
            break;
        }
    }

    tags
}

fn extract_source_location(file_location: &str) -> SourceLocation {
    let mut parts = file_location.split(':');
    let source_file = parts.next().unwrap_or("").to_string();
    let source_line = parts.next().unwrap_or("-1").to_string();
    SourceLocation {
        source_file,
        source_line,
    }
}

fn extract_debugged_function_signature(
    function: &FunctionEntry,
    type_map: &HashMap<i128, TypeEntry>,
) -> FunctionSignatureElems {
    let return_type = if let Some(return_addr) = function.type_arguments.first() {
        JsonValue::Array(
            extract_func_sig_friendly_type_tags(*return_addr, type_map)
                .into_iter()
                .map(JsonValue::String)
                .collect(),
        )
    } else {
        JsonValue::String("N/A".to_string())
    };

    let mut params: Vec<Vec<String>> = Vec::new();
    for argument_addr in function.type_arguments.iter().skip(1) {
        params.push(extract_func_sig_friendly_type_tags(*argument_addr, type_map));
    }

    FunctionSignatureElems { return_type, params }
}

fn convert_param_list_to_str_v2(param_list: &[String]) -> String {
    let mut pre = String::new();
    let mut med = String::new();
    let mut post = String::new();

    for param in param_list {
        match param.as_str() {
            "DW_TAG_pointer_type" => post.push('*'),
            "DW_TAG_reference_type" => post.push('&'),
            "DW_TAG_structure_type" => {
                med.push_str(" struct ");
            }
            "DW_TAG_base_type" | "DW_TAG_typedef" | "DW_TAG_class_type" => {}
            "DW_TAG_const_type" => pre.push_str("const "),
            "DW_TAG_enumeration_type" => {}
            _ => med.push_str(param),
        }
    }

    format!("{} {} {}", pre.trim(), med, post).trim().to_string()
}

fn is_struct(param_list: &[String]) -> bool {
    param_list
        .iter()
        .any(|param| param.as_str() == "DW_TAG_structure_type")
}

fn is_enumeration(param_list: &[String]) -> bool {
    param_list
        .iter()
        .any(|param| param.as_str() == "DW_TAG_enumeration_type")
}

fn write_all_friendly_debug_types(index: &TypeIndex, out_dir: &Path) -> Result<String, AppError> {
    fs::create_dir_all(out_dir).map_err(|err| {
        AppError::new(
            "io_error",
            format!("failed creating out_dir {}: {err}", out_dir.display()),
        )
    })?;

    let output_path = out_dir.join("all-friendly-debug-types.json");

    // Pre-pass: build member_entries_by_scope index (sequential, cheap).
    let mut member_entries_by_scope: HashMap<i128, Vec<(i128, String, i128)>> = HashMap::new();
    for type_entry in index.entries.values() {
        if type_entry.tag != "DW_TAG_member" {
            continue;
        }
        member_entries_by_scope
            .entry(type_entry.scope)
            .or_default()
            .push((type_entry.addr, type_entry.name.clone(), type_entry.base_type_addr));
    }

    // Phase 1: compute friendly-type tag chains for every address in parallel.
    // Result is an immutable HashMap reused by phase 2.
    let friendly_types: HashMap<i128, Vec<String>> = index
        .addr_order
        .par_iter()
        .map(|addr| {
            let tags = extract_func_sig_friendly_type_tags(*addr, &index.entries);
            (*addr, tags)
        })
        .collect();

    // Phases 2+3 interleaved: process addr_order in chunks so at most
    // WRITE_CHUNK_SIZE computed JsonValue entries are live in memory at once.
    // Within each chunk, entries are built in parallel; the chunk Vec is dropped
    // before the next chunk is computed, bounding peak memory to O(chunk_size)
    // rather than O(all_types) as a single flat collect would require.
    const WRITE_CHUNK_SIZE: usize = 8_000;

    let output_file = File::create(&output_path).map_err(|err| {
        AppError::new(
            "io_error",
            format!("failed creating {}: {err}", output_path.display()),
        )
    })?;
    let mut writer = BufWriter::new(output_file);

    writer.write_all(b"{").map_err(|err| {
        AppError::new("io_error", format!("failed writing output JSON header: {err}"))
    })?;

    let mut written_entries = 0usize;

    for chunk in index.addr_order.chunks(WRITE_CHUNK_SIZE) {
        // Parallel compute for this chunk only — Vec is dropped at end of iteration.
        let computed: Vec<Option<(i128, JsonValue)>> = chunk
            .par_iter()
            .map(|addr| {
                let debug_entry = index.entries.get(addr)?;
                let friendly_type =
                    friendly_types.get(addr).map(Vec::as_slice).unwrap_or(&[]);
                let is_struct_type = is_struct(friendly_type);

                let structure_elems: Vec<JsonValue> = if is_struct_type {
                    member_entries_by_scope
                        .get(addr)
                        .map(|members| {
                            members
                                .iter()
                                .map(|(member_addr, elem_name, base_type_addr)| {
                                    let elem_tags: Vec<String> = friendly_types
                                        .get(base_type_addr)
                                        .cloned()
                                        .unwrap_or_else(|| {
                                            extract_func_sig_friendly_type_tags(
                                                *base_type_addr,
                                                &index.entries,
                                            )
                                        });
                                    json!({
                                        "addr": member_addr,
                                        "elem_name": elem_name,
                                        "elem_friendly_type":
                                            convert_param_list_to_str_v2(&elem_tags),
                                    })
                                })
                                .collect()
                        })
                        .unwrap_or_default()
                } else {
                    Vec::new()
                };

                let entry = json!({
                    "raw_debug_info": debug_entry.raw_debug_info,
                    "friendly-info": {
                        "raw-types": friendly_type,
                        "string_type": convert_param_list_to_str_v2(friendly_type),
                        "is-struct": is_struct_type,
                        "struct-elems": structure_elems,
                        "is-enum": is_enumeration(friendly_type),
                        "enum-elems": debug_entry.enum_elems,
                    }
                });

                Some((*addr, entry))
            })
            .collect();

        // Sequential write for this chunk.
        for maybe_entry in computed {
            let Some((addr, entry)) = maybe_entry else {
                continue;
            };
            if written_entries > 0 {
                writer.write_all(b",").map_err(|err| {
                    AppError::new(
                        "io_error",
                        format!("failed writing output JSON separator: {err}"),
                    )
                })?;
            }
            serde_json::to_writer(&mut writer, &addr.to_string()).map_err(|err| {
                AppError::new(
                    "io_error",
                    format!("failed serializing friendly type key for {addr}: {err}"),
                )
            })?;
            writer.write_all(b":").map_err(|err| {
                AppError::new(
                    "io_error",
                    format!("failed writing output JSON colon: {err}"),
                )
            })?;
            serde_json::to_writer(&mut writer, &entry).map_err(|err| {
                AppError::new(
                    "io_error",
                    format!("failed serializing friendly type entry for {addr}: {err}"),
                )
            })?;
            written_entries += 1;
        }
        // `computed` Vec is dropped here — memory freed before next chunk.
    }

    writer.write_all(b"}").map_err(|err| {
        AppError::new("io_error", format!("failed writing output JSON trailer: {err}"))
    })?;
    writer.flush().map_err(|err| {
        AppError::new(
            "io_error",
            format!("failed flushing {}: {err}", output_path.display()),
        )
    })?;

    Ok(output_path.to_string_lossy().into_owned())
}

fn correlate_and_write_shards(
    functions: &[FunctionEntry],
    unique_row_indices: &[usize],
    row_to_unique_idx: &[usize],
    type_map: &HashMap<i128, TypeEntry>,
    output_dir: &Path,
    shard_size: usize,
) -> Result<CorrelationWriteResult, AppError> {
    fs::create_dir_all(output_dir).map_err(|err| {
        AppError::new(
            "io_error",
            format!("failed creating output_dir {}: {err}", output_dir.display()),
        )
    })?;

    let mut result = CorrelationWriteResult::default();

    // Phase 1: parallel type correlation (unchanged).
    let correlate_started = Instant::now();
    let unique_records =
        correlate_chunk_parallel_by_index(functions, unique_row_indices, type_map);
    result.correlate_ms += to_ms(correlate_started.elapsed());

    // Phase 2: write every shard in parallel — each shard is an independent file.
    // rayon's par_chunks preserves chunk order, so correlated_shards is ordered.
    let write_started = Instant::now();

    // Collect chunks with their index so we can reconstruct the absolute func_idx
    // inside each parallel task without needing a shared counter.
    let chunks: Vec<(usize, &[usize])> =
        row_to_unique_idx.chunks(shard_size).enumerate().collect();

    let shard_results: Vec<Result<(String, usize), AppError>> = chunks
        .par_iter()
        .map(|(shard_idx, chunk_indices)| {
            if chunk_indices.is_empty() {
                return Ok(("".to_string(), 0usize));
            }

            let shard_path =
                output_dir.join(format!("correlated-debug-{:05}.ndjson", shard_idx));
            let shard_file = File::create(&shard_path).map_err(|err| {
                AppError::new(
                    "io_error",
                    format!("failed creating shard {}: {err}", shard_path.display()),
                )
            })?;
            let mut writer = BufWriter::new(shard_file);
            let mut written = 0usize;

            for (i, &unique_idx) in chunk_indices.iter().enumerate() {
                let func_idx = shard_idx * shard_size + i;
                let function = &functions[func_idx];
                let cached_record = &unique_records[unique_idx];
                let record = CorrelatedRecord {
                    row_idx: function.original_row_idx,
                    func_signature_elems: cached_record.func_signature_elems.clone(),
                    source: cached_record.source.clone(),
                };
                serde_json::to_writer(&mut writer, &record).map_err(|err| {
                    AppError::new(
                        "io_error",
                        format!(
                            "failed serializing shard record {}: {err}",
                            shard_path.display()
                        ),
                    )
                })?;
                writer.write_all(b"\n").map_err(|err| {
                    AppError::new(
                        "io_error",
                        format!("failed writing shard line {}: {err}", shard_path.display()),
                    )
                })?;
                written += 1;
            }
            writer.flush().map_err(|err| {
                AppError::new(
                    "io_error",
                    format!("failed flushing shard {}: {err}", shard_path.display()),
                )
            })?;

            Ok((shard_path.to_string_lossy().into_owned(), written))
        })
        .collect();

    result.write_ms = to_ms(write_started.elapsed());

    // Aggregate results in chunk order (par_iter + collect preserves order).
    for shard_result in shard_results {
        let (path, count) = shard_result?;
        if !path.is_empty() {
            result.correlated_shards.push(path);
            result.written_records += count;
        }
    }

    Ok(result)
}



fn correlate_chunk_parallel_by_index(
    function_chunk: &[FunctionEntry],
    unique_row_indices: &[usize],
    type_map: &HashMap<i128, TypeEntry>,
) -> Vec<CachedCorrelationResult> {
    // rayon par_iter preserves order, so no post-sort or fallback path needed.
    unique_row_indices
        .par_iter()
        .map(|row_idx| {
            let function = &function_chunk[*row_idx];
            CachedCorrelationResult {
                func_signature_elems: extract_debugged_function_signature(function, type_map),
                source: extract_source_location(&function.file_location),
            }
        })
        .collect()
}

fn string_field(record: &JsonValue, key: &str) -> String {
    record
        .get(key)
        .and_then(JsonValue::as_str)
        .unwrap_or("")
        .to_string()
}

fn normalize_path_text(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }

    let absolute = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(part),
        }
    }

    let normalized = parts.join("/");
    if absolute {
        format!("/{normalized}")
    } else if normalized.is_empty() {
        ".".to_string()
    } else {
        normalized
    }
}

fn json_string_array(values: &[String]) -> JsonValue {
    JsonValue::Array(values.iter().cloned().map(JsonValue::String).collect())
}

fn extract_header_candidate_names(line: &str) -> Vec<String> {
    let mut names = Vec::new();
    for paren_idx in line.match_indices('(').map(|(idx, _)| idx) {
        let prefix = &line[..paren_idx];
        let mut name_chars = Vec::new();
        for ch in prefix.chars().rev() {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == ':' || ch == '~' {
                name_chars.push(ch);
            } else if !name_chars.is_empty() {
                break;
            }
        }
        if name_chars.is_empty() {
            continue;
        }
        name_chars.reverse();
        let candidate: String = name_chars.into_iter().collect();
        let first = candidate.chars().next().unwrap_or('\0');
        if first.is_ascii_alphabetic() || first == '_' || first == '~' {
            names.push(candidate);
        }
    }
    names
}

fn build_header_index(all_files_in_project: &[JsonValue]) -> HashMap<String, HashSet<String>> {
    let mut header_index: HashMap<String, HashSet<String>> = HashMap::new();
    for file_record in all_files_in_project {
        let source_file = file_record
            .get("source_file")
            .and_then(JsonValue::as_str)
            .unwrap_or("");
        if source_file.is_empty() || !(source_file.ends_with(".h") || source_file.ends_with(".hpp")) {
            continue;
        }
        let normalized_source_file = normalize_path_text(source_file);
        let Ok(content) = fs::read_to_string(&normalized_source_file) else {
            continue;
        };
        for line in content.lines() {
            for candidate in extract_header_candidate_names(line) {
                header_index
                    .entry(candidate.clone())
                    .or_default()
                    .insert(normalized_source_file.clone());
                if let Some((_, short_name)) = candidate.rsplit_once("::") {
                    header_index
                        .entry(short_name.to_string())
                        .or_default()
                        .insert(normalized_source_file.clone());
                }
            }
        }
    }
    header_index
}

fn normalize_debug_function(
    debug_function: &mut JsonValue,
    header_index_by_name: &HashMap<String, HashSet<String>>,
) {
    let debug_name = string_field(debug_function, "name");
    if let Some(object) = debug_function.as_object_mut() {
        let mut possible_headers: Vec<String> = header_index_by_name
            .get(&debug_name)
            .map(|headers| headers.iter().cloned().collect())
            .unwrap_or_default();
        possible_headers.sort();
        object.insert(
            "possible-header-files".to_string(),
            json_string_array(&possible_headers),
        );
        if let Some(source) = object.get_mut("source").and_then(JsonValue::as_object_mut) {
            let source_file = source
                .get("source_file")
                .and_then(JsonValue::as_str)
                .unwrap_or("");
            source.insert(
                "source_file".to_string(),
                JsonValue::String(normalize_path_text(source_file)),
            );
        }
    }
}

fn debug_source_file(debug_function: &JsonValue) -> String {
    debug_function
        .get("source")
        .and_then(|source| source.get("source_file"))
        .and_then(JsonValue::as_str)
        .map(normalize_path_text)
        .unwrap_or_default()
}

fn debug_source_line(debug_function: &JsonValue) -> Option<i64> {
    debug_function
        .get("source")
        .and_then(|source| source.get("source_line"))
        .and_then(parse_i64)
}

fn build_if_debug_indexes(
    debug_functions: &[JsonValue],
) -> (
    HashMap<String, Vec<usize>>,
    HashMap<String, Vec<usize>>,
    HashMap<String, Vec<(i64, usize)>>,
) {
    let mut debug_by_name: HashMap<String, Vec<usize>> = HashMap::new();
    let mut debug_by_filename: HashMap<String, Vec<usize>> = HashMap::new();
    let mut debug_lines_by_filename: HashMap<String, Vec<(i64, usize)>> = HashMap::new();

    for (idx, debug_function) in debug_functions.iter().enumerate() {
        let debug_name = string_field(debug_function, "name");
        let source_file = debug_source_file(debug_function);

        debug_by_name.entry(debug_name).or_default().push(idx);
        debug_by_filename
            .entry(source_file.clone())
            .or_default()
            .push(idx);
        if let Some(source_line) = debug_source_line(debug_function) {
            debug_lines_by_filename
                .entry(source_file)
                .or_default()
                .push((source_line, idx));
        }
    }

    for line_pairs in debug_lines_by_filename.values_mut() {
        line_pairs.sort_by_key(|(line, _)| *line);
    }

    (debug_by_name, debug_by_filename, debug_lines_by_filename)
}

fn push_name_candidate(candidates: &mut Vec<String>, raw_name: &str) {
    let candidate = raw_name.split('(').next().unwrap_or("").trim();
    if candidate.is_empty() {
        return;
    }
    if !candidates.iter().any(|existing| existing == candidate) {
        candidates.push(candidate.to_string());
    }
    if let Some((_, short_name)) = candidate.rsplit_once("::") {
        if !short_name.is_empty() && !candidates.iter().any(|existing| existing == short_name) {
            candidates.push(short_name.to_string());
        }
    }
}

fn introspection_debug_name_candidates(if_func: &JsonValue) -> Vec<String> {
    let mut candidates = Vec::new();
    push_name_candidate(&mut candidates, &string_field(if_func, "Func name"));
    push_name_candidate(&mut candidates, &string_field(if_func, "raw-function-name"));
    candidates
}

fn debug_function_name_matches(if_func: &JsonValue, debug_function: &JsonValue) -> bool {
    let debug_name = string_field(debug_function, "name");
    !debug_name.is_empty()
        && introspection_debug_name_candidates(if_func)
            .iter()
            .any(|candidate| candidate == &debug_name)
}

fn function_signature_elems(debug_function: &JsonValue) -> Option<(Vec<String>, Vec<Vec<String>>)> {
    let elems = debug_function.get("func_signature_elems")?.as_object()?;
    let return_type = elems
        .get("return_type")?
        .as_array()?
        .iter()
        .filter_map(JsonValue::as_str)
        .map(str::to_string)
        .collect::<Vec<String>>();
    let params = elems
        .get("params")?
        .as_array()?
        .iter()
        .map(|param| {
            param
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(JsonValue::as_str)
                        .map(str::to_string)
                        .collect::<Vec<String>>()
                })
                .unwrap_or_default()
        })
        .collect::<Vec<Vec<String>>>();
    Some((return_type, params))
}

fn extract_namespace_from_name(raw_name: &str, return_type: &str) -> Vec<String> {
    let mut demangled_name = raw_name.trim().to_string();
    let return_type_prefix = format!("{return_type} ");
    if !return_type.is_empty() && demangled_name.starts_with(&return_type_prefix) {
        demangled_name = demangled_name[return_type_prefix.len()..].to_string();
    }
    if !demangled_name.contains("::") {
        return Vec::new();
    }

    let mut namespaces = Vec::new();
    for elem in demangled_name.split("::") {
        if elem.is_empty() {
            continue;
        }
        if elem.starts_with('(') {
            namespaces.push(elem.to_string());
        } else if let Some((name, _)) = elem.split_once('(') {
            namespaces.push(name.to_string());
            break;
        } else {
            namespaces.push(elem.to_string());
        }
    }
    namespaces
}

fn extract_namespace(if_func: &JsonValue, return_type: &str) -> Vec<String> {
    for key in ["Func name", "raw-function-name"] {
        let namespace = extract_namespace_from_name(&string_field(if_func, key), return_type);
        if !namespace.is_empty() {
            return namespace;
        }
    }
    Vec::new()
}

fn set_json_string(object: &mut JsonValue, key: &str, value: String) {
    if let Some(map) = object.as_object_mut() {
        map.insert(key.to_string(), JsonValue::String(value));
    }
}

fn set_json_string_list(object: &mut JsonValue, key: &str, values: Vec<String>) {
    if let Some(map) = object.as_object_mut() {
        map.insert(key.to_string(), json_string_array(&values));
    }
}

fn convert_debug_info_to_signature(debug_function: &JsonValue, if_func: &JsonValue) -> (String, JsonValue) {
    let mut debug_info = debug_function.clone();
    let Some((return_type_tags, params)) = function_signature_elems(debug_function) else {
        return ("N/A".to_string(), debug_info);
    };

    let return_type = convert_param_list_to_str_v2(&return_type_tags);
    set_json_string(&mut debug_info, "return_type", return_type.clone());

    let namespace = extract_namespace(if_func, &return_type);
    let mut function_prefix = String::new();
    let mut param_idx = 0usize;
    let mut debug_name = string_field(debug_function, "name");

    if !params.is_empty() && namespace.len() > 1 {
        let first_param = convert_param_list_to_str_v2(&params[0]);
        let first_param_without_pointer = first_param.replace(" *", "");
        let last_namespace = namespace.last().map(String::as_str).unwrap_or("");
        let parent_namespace = namespace
            .get(namespace.len().saturating_sub(2))
            .map(String::as_str)
            .unwrap_or("");

        if last_namespace == first_param_without_pointer {
            function_prefix = format!("{}::", namespace[..namespace.len() - 1].join("::"));
            param_idx += 1;
        } else if last_namespace.contains('~')
            && last_namespace.replace('~', "") == first_param_without_pointer
        {
            function_prefix = format!("{}::", namespace[..namespace.len() - 1].join("::"));
            if first_param != "~" {
                debug_name = format!("~{debug_name}");
                set_json_string(&mut debug_info, "name", debug_name.clone());
            }
            param_idx += 1;
        } else if parent_namespace == first_param_without_pointer.replace("const ", "") {
            function_prefix = format!("{}::", namespace[..namespace.len() - 1].join("::"));
            param_idx += 1;
        } else {
            function_prefix = format!("{}::", namespace[..namespace.len() - 1].join("::"));
        }
    }

    let mut args = Vec::new();
    let mut signature = format!("{return_type} {function_prefix}{debug_name}(");
    for (idx, param) in params.iter().enumerate().skip(param_idx) {
        let param_string = convert_param_list_to_str_v2(param);
        args.push(param_string.clone());
        signature.push_str(&param_string);
        if idx < params.len() - 1 {
            signature.push_str(", ");
        }
    }
    signature.push(')');
    set_json_string_list(&mut debug_info, "args", args);
    (signature, debug_info)
}

fn correlate_if_func_to_debug_information(
    if_func: &JsonValue,
    debug_functions: &[JsonValue],
    debug_by_name: &HashMap<String, Vec<usize>>,
    debug_by_filename: &HashMap<String, Vec<usize>>,
    debug_lines_by_filename: &HashMap<String, Vec<(i64, usize)>>,
) -> Option<(String, JsonValue)> {
    let mut seen_debug_functions: HashSet<usize> = HashSet::new();
    for candidate_name in introspection_debug_name_candidates(if_func) {
        for debug_idx in debug_by_name.get(&candidate_name).into_iter().flatten() {
            if !seen_debug_functions.insert(*debug_idx) {
                continue;
            }
            return Some(convert_debug_info_to_signature(
                &debug_functions[*debug_idx],
                if_func,
            ));
        }
    }

    let source_file = normalize_path_text(&string_field(if_func, "Functions filename"));
    let source_line_begin = if_func.get("source_line_begin").and_then(parse_i64)?;

    if let Some(line_pairs) = debug_lines_by_filename.get(&source_file) {
        let exact_line_idx = match line_pairs.binary_search_by_key(&source_line_begin, |(line, _)| *line) {
            Ok(idx) | Err(idx) => idx,
        };
        if exact_line_idx < line_pairs.len()
            && line_pairs[exact_line_idx].0 == source_line_begin
            && source_line_begin != 0
        {
            let debug_idx = line_pairs[exact_line_idx].1;
            if debug_function_name_matches(if_func, &debug_functions[debug_idx]) {
                return Some(convert_debug_info_to_signature(&debug_functions[debug_idx], if_func));
            }
        }
        if exact_line_idx > 0 {
            let debug_idx = line_pairs[exact_line_idx - 1].1;
            if debug_function_name_matches(if_func, &debug_functions[debug_idx]) {
                return Some(convert_debug_info_to_signature(&debug_functions[debug_idx], if_func));
            }
        }
    }

    let mut target_minimum = i64::MAX;
    let mut most_likely: Option<(String, JsonValue)> = None;
    for debug_idx in debug_by_filename.get(&source_file).into_iter().flatten() {
        let debug_function = &debug_functions[*debug_idx];
        if !debug_function_name_matches(if_func, debug_function) {
            continue;
        }
        let Some(debug_line) = debug_source_line(debug_function) else {
            continue;
        };
        let distance = source_line_begin - debug_line;
        if distance == 0 && debug_line != 0 {
            return Some(convert_debug_info_to_signature(debug_function, if_func));
        }
        if distance > 0 && distance < target_minimum {
            most_likely = Some(convert_debug_info_to_signature(debug_function, if_func));
            target_minimum = distance;
        }
    }
    most_likely
}

fn run_if_debug_signature_request(request: Request) -> Result<Response, AppError> {
    let total_started = Instant::now();
    let mut timings = Timings::default();
    let mut counters = Counters::default();
    let mut artifacts = Artifacts::default();

    let parse_started = Instant::now();
    let mut debug_functions = if request.debug_functions_paths.is_empty() {
        request.debug_functions.clone()
    } else {
        load_records_from_paths(&request.debug_functions_paths)?
    };
    counters.parsed_functions = debug_functions.len();

    let header_index_by_name = build_header_index(&request.all_files_in_project);
    for debug_function in debug_functions.iter_mut() {
        normalize_debug_function(debug_function, &header_index_by_name);
    }
    let (debug_by_name, debug_by_filename, debug_lines_by_filename) =
        build_if_debug_indexes(&debug_functions);
    timings.parse_ms = to_ms(parse_started.elapsed());

    let project_language = request.project_language.as_deref().unwrap_or("");
    let correlate_started = Instant::now();
    artifacts.function_updates = request
        .introspection_functions
        .par_iter()
        .enumerate()
        .map(|(row_idx, if_func)| {
            let (function_signature, debug_function_info) = match correlate_if_func_to_debug_information(
                if_func,
                &debug_functions,
                &debug_by_name,
                &debug_by_filename,
                &debug_lines_by_filename,
            ) {
                Some((signature, debug_info)) => (signature, debug_info),
                None if project_language == "jvm" => (
                    string_field(if_func, "Func name"),
                    JsonValue::Object(serde_json::Map::new()),
                ),
                None => {
                    let existing_signature = string_field(if_func, "function_signature");
                    let fallback_signature = if existing_signature.is_empty() {
                        "N/A".to_string()
                    } else {
                        existing_signature
                    };
                    (fallback_signature, JsonValue::Object(serde_json::Map::new()))
                }
            };
            json!({
                "row_idx": row_idx,
                "function_signature": function_signature,
                "debug_function_info": debug_function_info,
            })
        })
        .collect();
    timings.correlate_ms = to_ms(correlate_started.elapsed());

    counters.updated_functions = artifacts.function_updates.len();
    counters.correlated_functions = artifacts
        .function_updates
        .iter()
        .filter(|update| {
            update
                .get("debug_function_info")
                .and_then(JsonValue::as_object)
                .map(|debug_info| !debug_info.is_empty())
                .unwrap_or(false)
        })
        .count();
    timings.total_ms = to_ms(total_started.elapsed());

    Ok(build_ok_response(
        request.schema_version,
        counters,
        artifacts,
        timings,
    ))
}

fn resolve_output_dir(request: &Request) -> Result<PathBuf, AppError> {
    if let Some(output_dir) = &request.output_dir {
        if !output_dir.trim().is_empty() {
            return Ok(PathBuf::from(output_dir));
        }
    }

    if let Some(out_dir) = &request.out_dir {
        if !out_dir.trim().is_empty() {
            return Ok(PathBuf::from(out_dir));
        }
    }

    Err(AppError::new(
        "invalid_request",
        "missing required output_dir (or compatibility out_dir)",
    ))
}

fn build_ok_response(
    schema_version: i64,
    counters: Counters,
    artifacts: Artifacts,
    timings: Timings,
) -> Response {
    Response {
        schema_version,
        status: "success",
        counters,
        artifacts,
        timings,
        reason_code: None,
    }
}

fn build_error_response(
    schema_version: i64,
    reason_code: &str,
    timings: Timings,
) -> Response {
    Response {
        schema_version,
        status: "error",
        counters: Counters::default(),
        artifacts: Artifacts::default(),
        timings,
        reason_code: Some(reason_code.to_string()),
    }
}

fn run_request(request: Request) -> Result<Response, AppError> {
    if request.stage.as_deref() == Some("if_debug_signature_correlation") {
        return run_if_debug_signature_request(request);
    }

    let total_started = Instant::now();
    let mut timings = Timings::default();
    let mut counters = Counters::default();
    let mut artifacts = Artifacts::default();

    let shard_size = request.shard_size.unwrap_or(DEFAULT_SHARD_SIZE).max(1);
    let output_dir = resolve_output_dir(&request)?;

    let parse_started = Instant::now();
    let raw_type_records = if request.debug_types_paths.is_empty() {
        request.debug_types.clone()
    } else {
        load_records_from_paths(&request.debug_types_paths)?
    };
    let raw_function_records = if request.debug_functions_paths.is_empty() {
        request.debug_functions.clone()
    } else {
        load_records_from_paths(&request.debug_functions_paths)?
    };

    counters.parsed_types = raw_type_records.len();
    counters.parsed_functions = raw_function_records.len();

    let type_index = build_type_index(&raw_type_records);
    let parsed_functions: Vec<FunctionEntry> = raw_function_records
        .par_iter()
        .enumerate()
        .filter_map(|(row_idx, record)| parse_function_entry(record, row_idx))
        .collect();
    timings.parse_ms = to_ms(parse_started.elapsed());

    let dedupe_started = Instant::now();
    let (unique_row_indices, row_to_unique_idx) = build_correlation_plan(&parsed_functions);
    counters.deduped_functions = unique_row_indices.len();
    timings.dedupe_ms = to_ms(dedupe_started.elapsed());

    if request.dump_files {
        let friendly_output_dir = request
            .out_dir
            .as_ref()
            .filter(|path| !path.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| output_dir.clone());

        let write_started = Instant::now();
        artifacts.all_friendly_debug_types =
            Some(write_all_friendly_debug_types(&type_index, &friendly_output_dir)?);
        timings.write_ms += to_ms(write_started.elapsed());
    }

    let correlation_result =
        correlate_and_write_shards(&parsed_functions, &unique_row_indices, &row_to_unique_idx, &type_index.entries, &output_dir, shard_size)?;

    counters.written_records = correlation_result.written_records;
    counters.updated_functions = correlation_result.written_records;
    counters.correlated_functions = correlation_result.written_records;
    counters.shards = correlation_result.correlated_shards.len();
    artifacts.correlated_shards = correlation_result.correlated_shards;

    timings.correlate_ms += correlation_result.correlate_ms;
    timings.write_ms += correlation_result.write_ms;
    timings.total_ms = to_ms(total_started.elapsed());

    Ok(build_ok_response(
        request.schema_version,
        counters,
        artifacts,
        timings,
    ))
}

fn emit_response(response: &Response) {
    let mut stdout = io::stdout().lock();
    if serde_json::to_writer(&mut stdout, response).is_ok() {
        let _ = stdout.write_all(b"\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_correlate(functions: &[FunctionEntry], type_map: &HashMap<i128, TypeEntry>) -> Vec<CorrelatedRecord> {
        let (unique_row_indices, row_to_unique_idx) = build_correlation_plan(functions);
        let unique_records = correlate_chunk_parallel_by_index(functions, &unique_row_indices, type_map);

        let mut records: Vec<CorrelatedRecord> = Vec::with_capacity(functions.len());
        for (function, &unique_idx) in functions.iter().zip(row_to_unique_idx.iter()) {
            let cached_record = &unique_records[unique_idx];
            records.push(CorrelatedRecord {
                row_idx: function.original_row_idx,
                func_signature_elems: cached_record.func_signature_elems.clone(),
                source: cached_record.source.clone(),
            });
        }
        records
    }

    fn function_entry(row_idx: usize, file_location: &str) -> FunctionEntry {
        FunctionEntry {
            original_row_idx: row_idx,
            file_location: file_location.to_string(),
            type_arguments: Vec::new(),
        }
    }

    fn function_entry_with_types(
        row_idx: usize,
        file_location: &str,
        type_arguments: Vec<i128>,
    ) -> FunctionEntry {
        FunctionEntry {
            original_row_idx: row_idx,
            file_location: file_location.to_string(),
            type_arguments,
        }
    }

    fn if_debug_request(
        introspection_functions: Vec<JsonValue>,
        debug_functions: Vec<JsonValue>,
    ) -> Request {
        Request {
            schema_version: 1,
            stage: Some("if_debug_signature_correlation".to_string()),
            debug_types_paths: Vec::new(),
            debug_functions_paths: Vec::new(),
            debug_types: Vec::new(),
            debug_functions,
            output_dir: None,
            shard_size: None,
            dump_files: false,
            out_dir: None,
            introspection_functions,
            project_language: Some("c-cpp".to_string()),
            all_files_in_project: Vec::new(),
        }
    }

    #[test]
    fn if_debug_stage_returns_function_updates_without_output_dir() {
        let request = if_debug_request(
            vec![json!({
                "Func name": "target",
                "Functions filename": "/src/project/target.cc",
                "source_line_begin": "20",
            })],
            vec![json!({
                "name": "target",
                "source": {
                    "source_file": "/src/project/target.cc",
                    "source_line": "20",
                },
                "func_signature_elems": {
                    "return_type": ["DW_TAG_base_type", "int"],
                    "params": [],
                },
            })],
        );

        let response = run_request(request).expect("IF-debug request should succeed");

        assert_eq!(response.status, "success");
        assert_eq!(response.artifacts.function_updates.len(), 1);
        assert_eq!(
            response.artifacts.function_updates[0]["function_signature"],
            JsonValue::String("int target()".to_string())
        );
        assert_eq!(
            response.artifacts.function_updates[0]["debug_function_info"]["name"],
            JsonValue::String("target".to_string())
        );
    }

    #[test]
    fn if_debug_stage_uses_short_names_for_source_line_matches() {
        let request = if_debug_request(
            vec![json!({
                "Func name": "ns::target(int)",
                "Functions filename": "/src/project/target.cc",
                "source_line_begin": "25",
            })],
            vec![json!({
                "name": "target",
                "source": {
                    "source_file": "/src/project/target.cc",
                    "source_line": "10",
                },
                "func_signature_elems": {
                    "return_type": ["DW_TAG_base_type", "void"],
                    "params": [["DW_TAG_base_type", "int"]],
                },
            })],
        );

        let response = run_request(request).expect("IF-debug request should succeed");

        assert_eq!(response.artifacts.function_updates.len(), 1);
        assert_eq!(
            response.artifacts.function_updates[0]["function_signature"],
            JsonValue::String("void ns::target(int)".to_string())
        );
    }

    #[test]
    fn if_debug_stage_emits_na_for_unmatched_rows() {
        let request = if_debug_request(
            vec![json!({
                "Func name": "missing",
                "Functions filename": "/src/project/target.cc",
                "source_line_begin": "invalid",
            })],
            Vec::new(),
        );

        let response = run_request(request).expect("IF-debug request should succeed");

        assert_eq!(response.artifacts.function_updates.len(), 1);
        assert_eq!(
            response.artifacts.function_updates[0]["function_signature"],
            JsonValue::String("N/A".to_string())
        );
        assert!(response.artifacts.function_updates[0]["debug_function_info"]
            .as_object()
            .expect("debug info should be an object")
            .is_empty());
    }

    #[test]
    fn correlation_plan_keeps_all_rows_with_duplicate_keys() {
        let functions = vec![
            function_entry(0, "/src/a.c:10"),
            function_entry(1, "/src/a.c:10"),
            function_entry(2, "/src/b.c:20"),
            function_entry(3, "/src/a.c:10"),
        ];

        let (unique_row_indices, row_to_unique_idx) = build_correlation_plan(&functions);

        assert_eq!(unique_row_indices, vec![0, 2]);
        assert_eq!(row_to_unique_idx, vec![0, 0, 1, 0]);
    }

    #[test]
    fn correlated_records_keep_one_output_per_input_row() {
        let functions = vec![
            function_entry(0, "/src/a.c:10"),
            function_entry(1, "/src/a.c:10"),
            function_entry(2, "/src/a.c:10"),
        ];

        let records = test_correlate(&functions, &HashMap::new());
        let row_indexes: Vec<usize> = records.into_iter().map(|record| record.row_idx).collect();

        assert_eq!(row_indexes, vec![0, 1, 2]);
    }

    #[test]
    fn correlation_plan_considers_type_arguments_in_key() {
        let functions = vec![
            function_entry_with_types(0, "/src/a.c:10", vec![1, 2]),
            function_entry_with_types(1, "/src/a.c:10", vec![1, 3]),
            function_entry_with_types(2, "/src/a.c:10", vec![1, 2]),
        ];

        let (unique_row_indices, row_to_unique_idx) = build_correlation_plan(&functions);

        assert_eq!(unique_row_indices, vec![0, 1]);
        assert_eq!(row_to_unique_idx, vec![0, 1, 0]);
    }

    #[test]
    fn correlate_chunk_parallel_by_index_respects_unique_row_indices_order() {
        let functions = vec![
            function_entry_with_types(100, "/src/a.c:10", vec![1]),
            function_entry_with_types(101, "/src/b.c:20", vec![2]),
            function_entry_with_types(102, "/src/c.c:30", vec![3]),
            function_entry_with_types(103, "/src/d.c:40", vec![4]),
        ];
        let unique_row_indices = vec![3, 0, 2, 0];

        let records = correlate_chunk_parallel_by_index(&functions, &unique_row_indices, &HashMap::new());
        let record_sources: Vec<String> = records
            .into_iter()
            .map(|record| record.source.source_file)
            .collect();

        assert_eq!(
            record_sources,
            vec![
                "/src/d.c".to_string(),
                "/src/a.c".to_string(),
                "/src/c.c".to_string(),
                "/src/a.c".to_string(),
            ]
        );
    }

    #[test]
    fn correlate_chunk_with_cache_is_deterministic_across_runs() {
        let functions = vec![
            function_entry_with_types(10, "/src/a.c:10", vec![1, 2]),
            function_entry_with_types(20, "/src/a.c:10", vec![1, 2]),
            function_entry_with_types(30, "/src/b.c:30", vec![3]),
            function_entry_with_types(40, "/src/a.c:10", vec![1, 2]),
            function_entry_with_types(50, "/src/c.c:50", vec![4, 5]),
        ];

        let baseline = serde_json::to_string(&test_correlate(&functions, &HashMap::new()))
            .expect("failed to serialize baseline records");

        for _ in 0..10 {
            let current = serde_json::to_string(&test_correlate(&functions, &HashMap::new()))
                .expect("failed to serialize correlated records");
            assert_eq!(current, baseline);
        }
    }
}

fn main() {
    let started = Instant::now();
    let mut raw_payload = String::new();

    if let Err(err) = io::stdin().read_to_string(&mut raw_payload) {
        let mut timings = Timings::default();
        timings.total_ms = to_ms(started.elapsed());
        emit_response(&build_error_response(0, "io_error", timings));
        eprintln!("failed reading stdin: {err}");
        return;
    }

    let schema_version = extract_schema_version(&raw_payload);

    let request = match serde_json::from_str::<Request>(&raw_payload) {
        Ok(request) => request,
        Err(err) => {
            let mut timings = Timings::default();
            timings.total_ms = to_ms(started.elapsed());
            emit_response(&build_error_response(
                schema_version,
                "invalid_request",
                timings,
            ));
            eprintln!("invalid request payload: {err}");
            return;
        }
    };

    match run_request(request) {
        Ok(response) => emit_response(&response),
        Err(err) => {
            let mut timings = Timings::default();
            timings.total_ms = to_ms(started.elapsed());
            emit_response(&build_error_response(
                schema_version,
                err.reason_code,
                timings,
            ));
            eprintln!("{}: {}", err.reason_code, err.message);
        }
    }
}
