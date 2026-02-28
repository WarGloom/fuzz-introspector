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

#[derive(Hash, Eq, PartialEq)]
struct CorrelationKey {
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

fn to_ms(duration: std::time::Duration) -> u64 {
    duration.as_millis() as u64
}

fn available_worker_count() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .max(1)
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

    // Fallback for full JSON/YAML payloads.
    let file = File::open(path)
        .map_err(|err| AppError::new("io_error", format!("failed opening {path}: {err}")))?;
    let parsed = yaml_serde::from_reader::<_, JsonValue>(file).map_err(|err| {
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

    let worker_count = available_worker_count().min(paths.len());
    if worker_count <= 1 {
        let mut merged: Vec<JsonValue> = Vec::new();
        for path in paths {
            let mut records = parse_records_from_file(path)?;
            merged.append(&mut records);
        }
        return Ok(merged);
    }

    let mut indexed_results: Vec<(usize, Result<Vec<JsonValue>, AppError>)> = Vec::new();
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for worker_idx in 0..worker_count {
            handles.push(scope.spawn(move || {
                let mut worker_results: Vec<(usize, Result<Vec<JsonValue>, AppError>)> = Vec::new();
                for path_idx in (worker_idx..paths.len()).step_by(worker_count) {
                    worker_results.push((path_idx, parse_records_from_file(&paths[path_idx])));
                }
                worker_results
            }));
        }

        for handle in handles {
            match handle.join() {
                Ok(mut worker_results) => indexed_results.append(&mut worker_results),
                Err(_) => indexed_results.push((
                    usize::MAX,
                    Err(AppError::new(
                        "internal_error",
                        "worker thread panicked while loading debug files",
                    )),
                )),
            }
        }
    });

    let mut per_file: Vec<Vec<JsonValue>> = vec![Vec::new(); paths.len()];
    for (path_idx, records_result) in indexed_results {
        if path_idx == usize::MAX {
            return records_result;
        }
        per_file[path_idx] = records_result?;
    }

    let mut merged: Vec<JsonValue> = Vec::new();
    for mut records in per_file {
        merged.append(&mut records);
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
    let mut index = TypeIndex::default();

    for record in records {
        let Some(type_entry) = parse_type_entry(record) else {
            continue;
        };

        if !index.entries.contains_key(&type_entry.addr) {
            index.addr_order.push(type_entry.addr);
        }
        index.entries.insert(type_entry.addr, type_entry);
    }

    index
}

fn build_correlation_plan(functions: &[FunctionEntry]) -> (Vec<FunctionEntry>, Vec<usize>) {
    let mut unique_functions: Vec<FunctionEntry> = Vec::new();
    let mut row_to_unique_idx: Vec<usize> = Vec::with_capacity(functions.len());
    let mut key_to_unique_idx: HashMap<CorrelationKey, usize> = HashMap::new();

    for function in functions {
        let key = CorrelationKey {
            file_location: function.file_location.clone(),
            type_arguments: function.type_arguments.clone(),
        };
        let unique_idx = if let Some(existing_idx) = key_to_unique_idx.get(&key) {
            *existing_idx
        } else {
            let next_idx = unique_functions.len();
            unique_functions.push(function.clone());
            key_to_unique_idx.insert(key, next_idx);
            next_idx
        };
        row_to_unique_idx.push(unique_idx);
    }

    (unique_functions, row_to_unique_idx)
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

fn build_struct_members_for_scope(
    scope_addr: i128,
    type_map: &HashMap<i128, TypeEntry>,
    member_entries_by_scope: &HashMap<i128, Vec<(i128, String, i128)>>,
    friendly_type_cache: &mut HashMap<i128, Vec<String>>,
) -> Vec<JsonValue> {
    let mut struct_members: Vec<JsonValue> = Vec::new();
    if let Some(entries) = member_entries_by_scope.get(&scope_addr) {
        for (addr, elem_name, base_type_addr) in entries {
            let member_friendly_type = if let Some(cached) = friendly_type_cache.get(base_type_addr) {
                cached.clone()
            } else {
                let generated = extract_func_sig_friendly_type_tags(*base_type_addr, type_map);
                friendly_type_cache.insert(*base_type_addr, generated.clone());
                generated
            };

            struct_members.push(json!({
                "addr": addr,
                "elem_name": elem_name,
                "elem_friendly_type": convert_param_list_to_str_v2(&member_friendly_type),
            }));
        }
    }
    struct_members
}

fn write_all_friendly_debug_types(index: &TypeIndex, out_dir: &Path) -> Result<String, AppError> {
    fs::create_dir_all(out_dir).map_err(|err| {
        AppError::new(
            "io_error",
            format!("failed creating out_dir {}: {err}", out_dir.display()),
        )
    })?;

    let output_path = out_dir.join("all-friendly-debug-types.json");
    let output_file = File::create(&output_path).map_err(|err| {
        AppError::new(
            "io_error",
            format!("failed creating {}: {err}", output_path.display()),
        )
    })?;
    let mut writer = BufWriter::new(output_file);

    let mut member_entries_by_scope: HashMap<i128, Vec<(i128, String, i128)>> = HashMap::new();
    for type_entry in index.entries.values() {
        if type_entry.tag != "DW_TAG_member" {
            continue;
        }

        member_entries_by_scope
            .entry(type_entry.scope)
            .or_default()
            .push((
                type_entry.addr,
                type_entry.name.clone(),
                type_entry.base_type_addr,
            ));
    }

    let mut friendly_type_cache: HashMap<i128, Vec<String>> = HashMap::new();
    let mut struct_members_cache: HashMap<i128, Vec<JsonValue>> = HashMap::new();

    writer
        .write_all(b"{")
        .map_err(|err| AppError::new("io_error", format!("failed writing output JSON header: {err}")))?;

    let mut written_entries = 0usize;
    for addr in &index.addr_order {
        let Some(debug_entry) = index.entries.get(addr) else {
            continue;
        };

        let friendly_type = if let Some(cached) = friendly_type_cache.get(addr) {
            cached.clone()
        } else {
            let generated = extract_func_sig_friendly_type_tags(*addr, &index.entries);
            friendly_type_cache.insert(*addr, generated.clone());
            generated
        };

        let is_struct_type = is_struct(&friendly_type);
        let structure_elems = if is_struct_type {
            if let Some(cached) = struct_members_cache.get(addr) {
                cached.clone()
            } else {
                let generated = build_struct_members_for_scope(
                    *addr,
                    &index.entries,
                    &member_entries_by_scope,
                    &mut friendly_type_cache,
                );
                struct_members_cache.insert(*addr, generated.clone());
                generated
            }
        } else {
            Vec::new()
        };

        let entry = json!({
            "raw_debug_info": debug_entry.raw_debug_info,
            "friendly-info": {
                "raw-types": friendly_type,
                "string_type": convert_param_list_to_str_v2(
                    friendly_type_cache.get(addr).map(Vec::as_slice).unwrap_or(&[]),
                ),
                "is-struct": is_struct_type,
                "struct-elems": structure_elems,
                "is-enum": is_enumeration(friendly_type_cache.get(addr).map(Vec::as_slice).unwrap_or(&[])),
                "enum-elems": debug_entry.enum_elems,
            }
        });

        if written_entries > 0 {
            writer
                .write_all(b",")
                .map_err(|err| AppError::new("io_error", format!("failed writing output JSON separator: {err}")))?;
        }

        serde_json::to_writer(&mut writer, &addr.to_string()).map_err(|err| {
            AppError::new(
                "io_error",
                format!("failed serializing friendly type key for {addr}: {err}"),
            )
        })?;
        writer
            .write_all(b":")
            .map_err(|err| AppError::new("io_error", format!("failed writing output JSON colon: {err}")))?;
        serde_json::to_writer(&mut writer, &entry).map_err(|err| {
            AppError::new(
                "io_error",
                format!("failed serializing friendly type entry for {addr}: {err}"),
            )
        })?;

        written_entries += 1;
    }

    writer
        .write_all(b"}")
        .map_err(|err| AppError::new("io_error", format!("failed writing output JSON trailer: {err}")))?;
    writer
        .flush()
        .map_err(|err| AppError::new("io_error", format!("failed flushing {}: {err}", output_path.display())))?;

    Ok(output_path.to_string_lossy().into_owned())
}

fn correlate_and_write_shards(
    functions: &[FunctionEntry],
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

    for (shard_idx, function_chunk) in functions.chunks(shard_size).enumerate() {
        if function_chunk.is_empty() {
            continue;
        }

        let correlate_started = Instant::now();
        let correlated_chunk = correlate_chunk_with_cache(function_chunk, type_map);
        result.correlate_ms += to_ms(correlate_started.elapsed());

        let shard_path = output_dir.join(format!("correlated-debug-{:05}.ndjson", shard_idx));
        let shard_file = File::create(&shard_path).map_err(|err| {
            AppError::new(
                "io_error",
                format!("failed creating shard {}: {err}", shard_path.display()),
            )
        })?;

        let write_started = Instant::now();
        let mut writer = BufWriter::new(shard_file);
        for record in correlated_chunk {
            serde_json::to_writer(&mut writer, &record).map_err(|err| {
                AppError::new(
                    "io_error",
                    format!("failed serializing shard record {}: {err}", shard_path.display()),
                )
            })?;
            writer.write_all(b"\n").map_err(|err| {
                AppError::new(
                    "io_error",
                    format!("failed writing shard line {}: {err}", shard_path.display()),
                )
            })?;
            result.written_records += 1;
        }
        writer.flush().map_err(|err| {
            AppError::new(
                "io_error",
                format!("failed flushing shard {}: {err}", shard_path.display()),
            )
        })?;
        result.write_ms += to_ms(write_started.elapsed());
        result
            .correlated_shards
            .push(shard_path.to_string_lossy().into_owned());
    }

    Ok(result)
}

fn correlate_chunk_with_cache(
    function_chunk: &[FunctionEntry],
    type_map: &HashMap<i128, TypeEntry>,
) -> Vec<CorrelatedRecord> {
    if function_chunk.is_empty() {
        return Vec::new();
    }

    let (unique_functions, row_to_unique_idx) = build_correlation_plan(function_chunk);
    let unique_records = correlate_chunk_parallel(&unique_functions, type_map);

    let mut records: Vec<CorrelatedRecord> = Vec::with_capacity(function_chunk.len());
    for (chunk_offset, function) in function_chunk.iter().enumerate() {
        let cached_record = &unique_records[row_to_unique_idx[chunk_offset]];
        records.push(CorrelatedRecord {
            row_idx: function.original_row_idx,
            func_signature_elems: cached_record.func_signature_elems.clone(),
            source: cached_record.source.clone(),
        });
    }
    records
}

fn correlate_chunk_parallel(
    function_chunk: &[FunctionEntry],
    type_map: &HashMap<i128, TypeEntry>,
) -> Vec<CorrelatedRecord> {
    if function_chunk.is_empty() {
        return Vec::new();
    }

    let worker_count = available_worker_count().min(function_chunk.len());
    if worker_count <= 1 {
        return function_chunk
            .iter()
            .map(|function| CorrelatedRecord {
                row_idx: function.original_row_idx,
                func_signature_elems: extract_debugged_function_signature(function, type_map),
                source: extract_source_location(&function.file_location),
            })
            .collect();
    }

    let mut indexed_records: Vec<(usize, CorrelatedRecord)> =
        Vec::with_capacity(function_chunk.len());

    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for worker_idx in 0..worker_count {
            handles.push(scope.spawn(move || {
                let mut worker_records: Vec<(usize, CorrelatedRecord)> = Vec::new();
                for chunk_offset in (worker_idx..function_chunk.len()).step_by(worker_count) {
                    let function = &function_chunk[chunk_offset];
                    worker_records.push((
                        chunk_offset,
                        CorrelatedRecord {
                            row_idx: function.original_row_idx,
                            func_signature_elems: extract_debugged_function_signature(
                                function, type_map,
                            ),
                            source: extract_source_location(&function.file_location),
                        },
                    ));
                }
                worker_records
            }));
        }

        for handle in handles {
            if let Ok(mut worker_records) = handle.join() {
                indexed_records.append(&mut worker_records);
            }
        }
    });

    if indexed_records.len() != function_chunk.len() {
        return function_chunk
            .iter()
            .map(|function| CorrelatedRecord {
                row_idx: function.original_row_idx,
                func_signature_elems: extract_debugged_function_signature(function, type_map),
                source: extract_source_location(&function.file_location),
            })
            .collect();
    }

    indexed_records.sort_by_key(|(chunk_offset, _)| *chunk_offset);
    indexed_records
        .into_iter()
        .map(|(_, record)| record)
        .collect()
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
        .iter()
        .enumerate()
        .filter_map(|(row_idx, record)| parse_function_entry(record, row_idx))
        .collect();
    timings.parse_ms = to_ms(parse_started.elapsed());

    let dedupe_started = Instant::now();
    let (memoized_correlation_inputs, _) = build_correlation_plan(&parsed_functions);
    counters.deduped_functions = memoized_correlation_inputs.len();
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
        correlate_and_write_shards(&parsed_functions, &type_index.entries, &output_dir, shard_size)?;

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

    fn function_entry(row_idx: usize, file_location: &str) -> FunctionEntry {
        FunctionEntry {
            original_row_idx: row_idx,
            file_location: file_location.to_string(),
            type_arguments: Vec::new(),
        }
    }

    #[test]
    fn correlation_plan_keeps_all_rows_with_duplicate_keys() {
        let functions = vec![
            function_entry(0, "/src/a.c:10"),
            function_entry(1, "/src/a.c:10"),
            function_entry(2, "/src/b.c:20"),
            function_entry(3, "/src/a.c:10"),
        ];

        let (unique_functions, row_to_unique_idx) = build_correlation_plan(&functions);

        assert_eq!(unique_functions.len(), 2);
        assert_eq!(row_to_unique_idx, vec![0, 0, 1, 0]);
    }

    #[test]
    fn correlated_records_keep_one_output_per_input_row() {
        let functions = vec![
            function_entry(0, "/src/a.c:10"),
            function_entry(1, "/src/a.c:10"),
            function_entry(2, "/src/a.c:10"),
        ];

        let records = correlate_chunk_with_cache(&functions, &HashMap::new());
        let row_indexes: Vec<usize> = records.into_iter().map(|record| record.row_idx).collect();

        assert_eq!(row_indexes, vec![0, 1, 2]);
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
