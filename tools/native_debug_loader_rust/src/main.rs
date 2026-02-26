use std::collections::{BTreeMap, HashSet};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;

const FUNCTIONS_SECTION_START: &str = "## Functions defined in module";
const FUNCTIONS_SECTION_END: &str = "## Global variables";
const TYPES_SECTION_START: &str = "## Types defined in module";

#[derive(Debug)]
struct CliArgs {
    base_dir: Option<PathBuf>,
    debug_files: Vec<PathBuf>,
}

#[derive(Debug)]
struct DebugPayload {
    content_hash: u64,
    files: BTreeMap<String, FileEntry>,
    functions: BTreeMap<String, FunctionEntry>,
    global_variables: BTreeMap<String, GlobalVariableEntry>,
    types: BTreeMap<String, TypeEntry>,
}

#[derive(Debug)]
struct LoaderOutput {
    all_files_in_project: Vec<FileEntry>,
    all_functions_in_project: Vec<FunctionEntry>,
    all_global_variables: Vec<GlobalVariableEntry>,
    all_types: Vec<TypeEntry>,
}

#[derive(Debug, Clone)]
struct FileEntry {
    source_file: String,
    language: String,
}

#[derive(Debug, Clone)]
struct SourceLocation {
    source_file: String,
    source_line: String,
}

#[derive(Debug, Clone)]
struct FunctionEntry {
    name: String,
    source: SourceLocation,
    args: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
struct GlobalVariableEntry {
    name: String,
    source: SourceLocation,
}

#[derive(Debug, Clone)]
struct TypeElementEntry {
    name: String,
    source: SourceLocation,
}

#[derive(Debug, Clone)]
struct TypeEntry {
    kind: String,
    name: String,
    source: SourceLocation,
    elements: Vec<TypeElementEntry>,
}

#[derive(Debug)]
struct PendingTypeStruct {
    name: String,
    source: SourceLocation,
    elements: Vec<TypeElementEntry>,
}

#[derive(Debug)]
struct PendingFunction {
    name: String,
    source: Option<SourceLocation>,
    named_args: Vec<String>,
    operand_args: Vec<String>,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let cli = match parse_cli_args()? {
        Some(args) => args,
        None => return Ok(()),
    };

    if let Some(base_dir) = cli.base_dir.as_deref() {
        if !base_dir.exists() {
            return Err(format!(
                "--base-dir '{}' does not exist",
                base_dir.display()
            ));
        }
        if !base_dir.is_dir() {
            return Err(format!(
                "--base-dir '{}' is not a directory",
                base_dir.display()
            ));
        }
    }

    for file in &cli.debug_files {
        if !file.exists() {
            return Err(format!("debug file '{}' does not exist", file.display()));
        }
        if !file.is_file() {
            return Err(format!("debug file '{}' is not a file", file.display()));
        }
    }

    let output = load_debug_report(&cli.debug_files, cli.base_dir.as_deref())?;
    let json_output = render_loader_output(&output);

    io::stdout()
        .write_all(json_output.as_bytes())
        .and_then(|_| io::stdout().write_all(b"\n"))
        .map_err(|err| format!("failed to write JSON output: {err}"))?;

    Ok(())
}

fn usage(program: &str) -> String {
    format!(
        "Usage: {program} [--base-dir <path>] <debug_files...>\n\
         Example: {program} --base-dir /work a.debug b.debug"
    )
}

fn parse_cli_args() -> Result<Option<CliArgs>, String> {
    let mut argv = env::args();
    let program = argv
        .next()
        .unwrap_or_else(|| "native_debug_loader_rust".to_string());
    let mut base_dir: Option<PathBuf> = None;
    let mut debug_files: Vec<PathBuf> = Vec::new();
    let args: Vec<String> = argv.collect();

    if args.is_empty() {
        return Err(format!("No arguments provided.\n{}", usage(&program)));
    }

    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--help" || arg == "-h" {
            println!("{}", usage(&program));
            return Ok(None);
        }

        if arg == "--base-dir" {
            if base_dir.is_some() {
                return Err("--base-dir was provided more than once".to_string());
            }
            index += 1;
            let value = args.get(index).ok_or_else(|| {
                format!(
                    "Missing value for --base-dir.\n{}",
                    usage(&program)
                )
            })?;
            base_dir = Some(PathBuf::from(value));
            index += 1;
            continue;
        }

        if arg.starts_with("--") {
            return Err(format!("Unknown option '{arg}'.\n{}", usage(&program)));
        }

        debug_files.push(PathBuf::from(arg));
        index += 1;
    }

    if debug_files.is_empty() {
        return Err(format!("No debug files provided.\n{}", usage(&program)));
    }

    Ok(Some(CliArgs {
        base_dir,
        debug_files,
    }))
}

fn load_debug_report(debug_files: &[PathBuf], _base_dir: Option<&Path>) -> Result<LoaderOutput, String> {
    let mut all_files: BTreeMap<String, FileEntry> = BTreeMap::new();
    let mut all_functions: BTreeMap<String, FunctionEntry> = BTreeMap::new();
    let mut all_globals: BTreeMap<String, GlobalVariableEntry> = BTreeMap::new();
    let mut all_types: BTreeMap<String, TypeEntry> = BTreeMap::new();
    let mut seen_hashes: HashSet<u64> = HashSet::new();

    for debug_file in debug_files {
        let payload = load_debug_file_payload(debug_file)?;
        if !seen_hashes.insert(payload.content_hash) {
            continue;
        }

        all_files.extend(payload.files);
        all_functions.extend(payload.functions);
        all_globals.extend(payload.global_variables);
        all_types.extend(payload.types);
    }

    Ok(LoaderOutput {
        all_files_in_project: all_files.into_values().collect(),
        all_functions_in_project: all_functions.into_values().collect(),
        all_global_variables: all_globals.into_values().collect(),
        all_types: all_types.into_values().collect(),
    })
}

fn load_debug_file_payload(debug_file: &Path) -> Result<DebugPayload, String> {
    let raw_bytes = fs::read(debug_file).map_err(|err| {
        format!(
            "failed to read debug file '{}': {err}",
            debug_file.display()
        )
    })?;
    let raw_content = String::from_utf8_lossy(&raw_bytes).to_string();

    let mut files: BTreeMap<String, FileEntry> = BTreeMap::new();
    let mut functions: BTreeMap<String, FunctionEntry> = BTreeMap::new();
    let mut global_variables: BTreeMap<String, GlobalVariableEntry> = BTreeMap::new();
    let mut types: BTreeMap<String, TypeEntry> = BTreeMap::new();

    extract_all_compile_units(&raw_content, &mut files);
    extract_all_functions_in_debug_info(&raw_content, &mut functions, &mut files);
    extract_global_variables(&raw_content, &mut global_variables, &mut files);
    extract_types(&raw_content, &mut types, &mut files);

    Ok(DebugPayload {
        content_hash: stable_content_hash(&raw_bytes),
        files,
        functions,
        global_variables,
        types,
    })
}

fn stable_content_hash(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    hash
}

fn extract_all_compile_units(content: &str, all_files_in_debug_info: &mut BTreeMap<String, FileEntry>) {
    for line in content.lines() {
        if !line.contains("Compile unit:") {
            continue;
        }

        let split_line: Vec<&str> = line.split(' ').collect();
        let language = split_line.get(2).copied().unwrap_or("N/A").to_string();
        let mut source_file = split_line.last().copied().unwrap_or("").to_string();

        if source_file.contains("//") {
            let pieces: Vec<&str> = source_file.split("//").collect();
            if pieces.len() > 1 {
                source_file = format!("/{}", pieces[1..].join("//"));
            }
        }

        if source_file.is_empty() {
            continue;
        }

        all_files_in_debug_info.insert(
            source_file.clone(),
            FileEntry {
                source_file,
                language,
            },
        );
    }
}

fn extract_global_variables(
    content: &str,
    global_variables: &mut BTreeMap<String, GlobalVariableEntry>,
    source_files: &mut BTreeMap<String, FileEntry>,
) {
    for line in content.lines() {
        let Some(without_prefix) = line.strip_prefix("Global variable: ") else {
            continue;
        };

        let pieces: Vec<&str> = without_prefix.split(" from ").collect();
        let global_variable_name = pieces.first().copied().unwrap_or("").to_string();
        let location = pieces.last().copied().unwrap_or("");
        let source_file = location.split(':').next().unwrap_or("").to_string();
        let source_line = location.split(':').nth(1).unwrap_or("-1").to_string();

        let key = format!("{}{}", source_file, source_line);
        global_variables.insert(
            key,
            GlobalVariableEntry {
                name: global_variable_name,
                source: SourceLocation {
                    source_file: source_file.clone(),
                    source_line,
                },
            },
        );

        source_files.entry(source_file.clone()).or_insert(FileEntry {
            source_file,
            language: "N/A".to_string(),
        });
    }
}

fn extract_types(
    content: &str,
    all_types: &mut BTreeMap<String, TypeEntry>,
    all_files_in_debug_info: &mut BTreeMap<String, FileEntry>,
) {
    let mut read_types = false;
    let mut current_struct: Option<PendingTypeStruct> = None;

    for line in content.lines() {
        if line.contains(TYPES_SECTION_START) {
            read_types = true;
        }

        if !read_types {
            continue;
        }

        if line.contains("Type: Name:") {
            if let Some(prev_struct) = current_struct.take() {
                let hashkey = format!(
                    "{}{}",
                    prev_struct.source.source_file, prev_struct.source.source_line
                );
                all_types.insert(
                    hashkey,
                    TypeEntry {
                        kind: "struct".to_string(),
                        name: prev_struct.name,
                        source: prev_struct.source,
                        elements: prev_struct.elements,
                    },
                );
            }

            if line.contains("DW_TAG_structure") {
                let struct_name = line
                    .split('{')
                    .last()
                    .unwrap_or("")
                    .split('}')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let location = line
                    .split("from")
                    .last()
                    .unwrap_or("")
                    .trim()
                    .split(' ')
                    .next()
                    .unwrap_or("");
                let source_file = location.split(':').next().unwrap_or("").to_string();
                let source_line = location.split(':').nth(1).unwrap_or("-1").to_string();
                let source = SourceLocation {
                    source_file: source_file.clone(),
                    source_line,
                };

                current_struct = Some(PendingTypeStruct {
                    name: struct_name,
                    source,
                    elements: Vec::new(),
                });

                all_files_in_debug_info.entry(source_file.clone()).or_insert(FileEntry {
                    source_file,
                    language: "N/A".to_string(),
                });
            }

            if line.contains("DW_TAG_typedef") {
                let name = line
                    .split('{')
                    .last()
                    .unwrap_or("")
                    .trim()
                    .split('}')
                    .next()
                    .unwrap_or("")
                    .to_string();
                let location = line
                    .split(" from ")
                    .last()
                    .unwrap_or("")
                    .split(' ')
                    .next()
                    .unwrap_or("");
                let source_file = location.split(':').next().unwrap_or("").to_string();
                let source_line = location.split(':').nth(1).unwrap_or("-1").to_string();
                let source = SourceLocation {
                    source_file: source_file.clone(),
                    source_line: source_line.clone(),
                };

                let hashkey = format!("{}{}", source_file, source_line);
                all_types.insert(
                    hashkey,
                    TypeEntry {
                        kind: "typedef".to_string(),
                        name,
                        source,
                        elements: Vec::new(),
                    },
                );

                all_files_in_debug_info.entry(source_file.clone()).or_insert(FileEntry {
                    source_file,
                    language: "N/A".to_string(),
                });
            }
        }

        if line.contains("- Elem ") {
            let Some(current) = current_struct.as_mut() else {
                continue;
            };

            let elem_name = line
                .split('{')
                .last()
                .unwrap_or("")
                .trim()
                .split(' ')
                .next()
                .unwrap_or("")
                .to_string();
            let location = line
                .split("from")
                .last()
                .unwrap_or("")
                .trim()
                .split(' ')
                .next()
                .unwrap_or("");
            let source_file = location.split(':').next().unwrap_or("").to_string();
            let source_line = location.split(':').nth(1).unwrap_or("-1").to_string();

            current.elements.push(TypeElementEntry {
                name: elem_name,
                source: SourceLocation {
                    source_file: source_file.clone(),
                    source_line,
                },
            });

            all_files_in_debug_info.entry(source_file.clone()).or_insert(FileEntry {
                source_file,
                language: "N/A".to_string(),
            });
        }
    }
}

fn extract_all_functions_in_debug_info(
    content: &str,
    all_functions_in_debug: &mut BTreeMap<String, FunctionEntry>,
    all_files_in_debug_info: &mut BTreeMap<String, FileEntry>,
) {
    let Some(mut section_start_idx) = content.find(FUNCTIONS_SECTION_START) else {
        return;
    };

    section_start_idx += FUNCTIONS_SECTION_START.len();
    if content
        .as_bytes()
        .get(section_start_idx)
        .copied()
        .is_some_and(|byte| byte == b'\n')
    {
        section_start_idx += 1;
    }

    let section_end_idx = content[section_start_idx..]
        .find(FUNCTIONS_SECTION_END)
        .map(|offset| section_start_idx + offset)
        .unwrap_or(content.len());
    let functions_section = &content[section_start_idx..section_end_idx];

    let mut current_function: Option<PendingFunction> = None;

    for line in functions_section.lines() {
        if let Some(function_name) = line.strip_prefix("Subprogram: ") {
            finalize_current_function(&mut current_function, all_functions_in_debug);
            current_function = Some(PendingFunction {
                name: function_name.trim().to_string(),
                source: None,
                named_args: Vec::new(),
                operand_args: Vec::new(),
            });
            continue;
        }

        let Some(current) = current_function.as_mut() else {
            continue;
        };

        if current.source.is_none() {
            if let Some((source_file, source_line)) = maybe_extract_source_location(line) {
                current.source = Some(SourceLocation {
                    source_file: source_file.clone(),
                    source_line,
                });

                all_files_in_debug_info
                    .entry(source_file.clone())
                    .or_insert(FileEntry {
                        source_file,
                        language: "N/A".to_string(),
                    });
            }
        }

        if let Some(named_arg) = maybe_extract_named_arg(line) {
            current.named_args.push(named_arg);
            continue;
        }

        if let Some(operand_type) = maybe_extract_operand_type(line) {
            current.operand_args.push(operand_type);
        }
    }

    finalize_current_function(&mut current_function, all_functions_in_debug);
}

fn finalize_current_function(
    current_function: &mut Option<PendingFunction>,
    all_functions_in_debug: &mut BTreeMap<String, FunctionEntry>,
) {
    let Some(current) = current_function.take() else {
        return;
    };

    let Some(source) = current.source else {
        return;
    };

    let args = if !current.named_args.is_empty() {
        current.named_args
    } else {
        current.operand_args
    };

    let function = FunctionEntry {
        name: current.name,
        source: source.clone(),
        args: (!args.is_empty()).then_some(args),
    };

    let hashkey = format!("{}{}", source.source_file, source.source_line);
    all_functions_in_debug.insert(hashkey, function);
}

fn maybe_extract_source_location(line: &str) -> Option<(String, String)> {
    if !line.contains(" from ") || line.contains(" - Operand") || line.contains("Elem ") {
        return None;
    }

    let location = line.rsplit(" from ").next()?.trim();
    let (source_file, source_line_tail) = location.split_once(':')?;
    if source_file.is_empty() {
        return None;
    }

    let digits: String = source_line_tail
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        return None;
    }

    Some((source_file.trim().to_string(), digits))
}

fn maybe_extract_named_arg(line: &str) -> Option<String> {
    const MARKER: &str = "Name: {";

    let start_idx = line.find(MARKER)? + MARKER.len();
    let end_idx = line[start_idx..].find('}')? + start_idx;
    let value = line[start_idx..end_idx].trim();
    if value.is_empty() {
        return None;
    }

    Some(value.to_string())
}

fn maybe_extract_operand_type(line: &str) -> Option<String> {
    if !line.contains(" - Operand") {
        return None;
    }

    let normalized = line
        .replace("Operand Type:", "")
        .replace("Type: ", "")
        .replace('-', "");
    let pointer_count = normalized.matches("DW_TAG_pointer_type").count();
    let const_count = normalized.matches("DW_TAG_const_type").count();

    let parts: Vec<&str> = normalized.split(',').collect();
    if parts.is_empty() {
        return None;
    }

    let base_type = parts.last().copied().unwrap_or("").trim();
    let mut output = String::new();
    if const_count > 0 {
        output.push_str("const ");
    }
    output.push_str(base_type);
    if pointer_count > 0 {
        output.push(' ');
        output.push_str(&"*".repeat(pointer_count));
    }

    if output.trim().is_empty() {
        None
    } else {
        Some(output)
    }
}

fn render_loader_output(output: &LoaderOutput) -> String {
    let files_json = output
        .all_files_in_project
        .iter()
        .map(render_file_entry)
        .collect::<Vec<_>>()
        .join(",");
    let functions_json = output
        .all_functions_in_project
        .iter()
        .map(render_function_entry)
        .collect::<Vec<_>>()
        .join(",");
    let globals_json = output
        .all_global_variables
        .iter()
        .map(render_global_variable_entry)
        .collect::<Vec<_>>()
        .join(",");
    let types_json = output
        .all_types
        .iter()
        .map(render_type_entry)
        .collect::<Vec<_>>()
        .join(",");

    format!(
        "{{\"all_files_in_project\":[{files_json}],\"all_functions_in_project\":[{functions_json}],\"all_global_variables\":[{globals_json}],\"all_types\":[{types_json}]}}"
    )
}

fn render_file_entry(entry: &FileEntry) -> String {
    format!(
        "{{\"source_file\":{},\"language\":{}}}",
        render_string(&entry.source_file),
        render_string(&entry.language)
    )
}

fn render_function_entry(entry: &FunctionEntry) -> String {
    let mut fields = vec![
        format!("\"name\":{}", render_string(&entry.name)),
        format!("\"source\":{}", render_source_location(&entry.source)),
    ];

    if let Some(args) = &entry.args {
        let args_json = args
            .iter()
            .map(|arg| render_string(arg))
            .collect::<Vec<_>>()
            .join(",");
        fields.push(format!("\"args\":[{args_json}]"));
    }

    format!("{{{}}}", fields.join(","))
}

fn render_global_variable_entry(entry: &GlobalVariableEntry) -> String {
    format!(
        "{{\"name\":{},\"source\":{}}}",
        render_string(&entry.name),
        render_source_location(&entry.source)
    )
}

fn render_type_entry(entry: &TypeEntry) -> String {
    let mut fields = vec![
        format!("\"type\":{}", render_string(&entry.kind)),
        format!("\"name\":{}", render_string(&entry.name)),
        format!("\"source\":{}", render_source_location(&entry.source)),
    ];

    if !entry.elements.is_empty() {
        let elements_json = entry
            .elements
            .iter()
            .map(render_type_element_entry)
            .collect::<Vec<_>>()
            .join(",");
        fields.push(format!("\"elements\":[{elements_json}]"));
    }

    format!("{{{}}}", fields.join(","))
}

fn render_type_element_entry(entry: &TypeElementEntry) -> String {
    format!(
        "{{\"name\":{},\"source\":{}}}",
        render_string(&entry.name),
        render_source_location(&entry.source)
    )
}

fn render_source_location(source: &SourceLocation) -> String {
    format!(
        "{{\"source_file\":{},\"source_line\":{}}}",
        render_string(&source.source_file),
        render_string(&source.source_line)
    )
}

fn render_string(value: &str) -> String {
    format!("\"{}\"", escape_json(value))
}

fn escape_json(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\u{08}' => escaped.push_str("\\b"),
            '\u{0c}' => escaped.push_str("\\f"),
            c if c <= '\u{1f}' => escaped.push_str(&format!("\\u{:04x}", c as u32)),
            c => escaped.push(c),
        }
    }
    escaped
}
