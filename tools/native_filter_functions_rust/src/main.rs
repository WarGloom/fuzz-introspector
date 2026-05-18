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

//! Native function-profile filter for fuzz-introspector.
//!
//! Reads a JSON payload from stdin describing profiles and exclusion
//! patterns, determines which profiles should be dropped entirely and
//! which individual functions within surviving profiles should be
//! excluded, then writes the exclusion lists to stdout as JSON.
//!
//! This replaces the O(profiles × functions × patterns) Python loop in
//! `analysis.py::load_data_files()` with parallel Rust regex matching.
//!
//! Protocol:
//!   - Input:  JSON on stdin  (see `Input` struct)
//!   - Output: JSON on stdout (see `Output` struct)
//!
//! Activation:
//!   - `FI_FILTER_BACKEND=rust` (or `FI_NATIVE_BACKENDS=rust`)
//!   - Binary located via `FI_FILTER_RUST_BIN` or `PATH` lookup.

use std::io::{self, Read, Write};

use log::{debug, error, info};
use rayon::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Input types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct Input {
    schema_version: u32,
    #[serde(default)]
    file_exclude_patterns: Vec<String>,
    #[serde(default)]
    function_exclude_patterns: Vec<String>,
    profiles: Vec<ProfileInput>,
}

#[derive(Debug, Deserialize)]
struct ProfileInput {
    profile_id: String,
    fuzzer_source_file: String,
    #[serde(default)]
    all_class_functions: Vec<FunctionEntry>,
    #[serde(default)]
    all_class_constructors: Vec<FunctionEntry>,
}

#[derive(Debug, Deserialize)]
struct FunctionEntry {
    key: String,
    function_source_file: String,
    function_name: String,
    raw_function_name: String,
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
    excluded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    excluded_functions: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    excluded_constructors: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Core filtering logic
// ---------------------------------------------------------------------------

fn matches_any(patterns: &[Regex], value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    patterns.iter().any(|p| p.is_match(value))
}

fn should_exclude_function(
    file_patterns: &[Regex],
    func_patterns: &[Regex],
    entry: &FunctionEntry,
) -> bool {
    if matches_any(file_patterns, &entry.function_source_file) {
        return true;
    }
    if matches_any(func_patterns, &entry.function_name) {
        return true;
    }
    if matches_any(func_patterns, &entry.raw_function_name) {
        return true;
    }
    false
}

fn filter_profile(
    file_patterns: &[Regex],
    func_patterns: &[Regex],
    profile: &ProfileInput,
) -> ProfileOutput {
    // First check if the entire profile should be excluded.
    if matches_any(file_patterns, &profile.fuzzer_source_file) {
        return ProfileOutput {
            profile_id: profile.profile_id.clone(),
            excluded: true,
            excluded_functions: None,
            excluded_constructors: None,
        };
    }

    let excluded_functions: Vec<String> = profile
        .all_class_functions
        .par_iter()
        .filter(|f| should_exclude_function(file_patterns, func_patterns, f))
        .map(|f| f.key.clone())
        .collect();

    let excluded_constructors: Vec<String> = profile
        .all_class_constructors
        .par_iter()
        .filter(|f| should_exclude_function(file_patterns, func_patterns, f))
        .map(|f| f.key.clone())
        .collect();

    ProfileOutput {
        profile_id: profile.profile_id.clone(),
        excluded: false,
        excluded_functions: Some(excluded_functions),
        excluded_constructors: Some(excluded_constructors),
    }
}

fn write_error(reason: String) -> ! {
    let out = Output {
        schema_version: 1,
        status: "error".to_string(),
        profiles: None,
        reason: Some(reason),
    };
    let _ = writeln!(io::stdout(), "{}", serde_json::to_string(&out).unwrap());
    std::process::exit(1);
}

fn compile_input_patterns(
    patterns: &[String],
    pattern_kind: &str,
) -> Result<Vec<Regex>, String> {
    patterns
        .iter()
        .map(|pattern| {
            Regex::new(pattern).map_err(|err| {
                error!(
                    "Invalid {} exclude pattern {:?}: {}",
                    pattern_kind, pattern, err
                );
                format!(
                    "Invalid {} exclude pattern {:?}: {}",
                    pattern_kind, pattern, err
                )
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    env_logger::init();
    info!("native_filter_functions_rust starting");

    // Read all of stdin.
    let mut raw = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut raw) {
        write_error(format!("Failed to read stdin: {e}"));
    }

    // Parse JSON input.
    let input: Input = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            error!("JSON parse error: {e}");
            write_error(format!("JSON parse error: {e}"));
        }
    };

    if input.schema_version != 1 {
        write_error(format!(
            "Unsupported schema_version: {}",
            input.schema_version
        ));
    }

    // Compile regex patterns.
    let file_patterns = match compile_input_patterns(
        &input.file_exclude_patterns,
        "file",
    ) {
        Ok(patterns) => patterns,
        Err(reason) => write_error(reason),
    };

    let func_patterns = match compile_input_patterns(
        &input.function_exclude_patterns,
        "function",
    ) {
        Ok(patterns) => patterns,
        Err(reason) => write_error(reason),
    };

    info!(
        "Processing {} profile(s) with {} file patterns and {} function patterns",
        input.profiles.len(),
        file_patterns.len(),
        func_patterns.len(),
    );

    // Process profiles in parallel.
    let profile_outputs: Vec<ProfileOutput> = input
        .profiles
        .par_iter()
        .map(|profile| {
            debug!(
                "Profile '{}': {} functions, {} constructors",
                profile.profile_id,
                profile.all_class_functions.len(),
                profile.all_class_constructors.len(),
            );
            filter_profile(&file_patterns, &func_patterns, profile)
        })
        .collect();

    let excluded_count = profile_outputs.iter().filter(|p| p.excluded).count();
    let total_excluded_funcs: usize = profile_outputs
        .iter()
        .filter_map(|p| p.excluded_functions.as_ref())
        .map(|v| v.len())
        .sum();
    let total_excluded_ctors: usize = profile_outputs
        .iter()
        .filter_map(|p| p.excluded_constructors.as_ref())
        .map(|v| v.len())
        .sum();

    info!(
        "Filtering complete: {}/{} profiles excluded, {} functions excluded, {} constructors excluded",
        excluded_count,
        input.profiles.len(),
        total_excluded_funcs,
        total_excluded_ctors,
    );

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
            write_error(format!("JSON serialization error: {e}"));
        }
    };

    let stdout = io::stdout();
    let mut handle = stdout.lock();
    if let Err(e) = writeln!(handle, "{json}") {
        error!("Failed to write output: {e}");
        std::process::exit(1);
    }

    info!("native_filter_functions_rust done");
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_entry(key: &str, source: &str, fname: &str, raw: &str) -> FunctionEntry {
        FunctionEntry {
            key: key.to_string(),
            function_source_file: source.to_string(),
            function_name: fname.to_string(),
            raw_function_name: raw.to_string(),
        }
    }

    fn compile_patterns(patterns: &[&str]) -> Vec<Regex> {
        patterns.iter().map(|p| Regex::new(p).unwrap()).collect()
    }

    #[test]
    fn test_no_patterns_no_exclusions() {
        let file_pats: Vec<Regex> = vec![];
        let func_pats: Vec<Regex> = vec![];
        let entry = mk_entry("foo", "/src/foo.cc", "foo", "_Z3foov");
        assert!(!should_exclude_function(&file_pats, &func_pats, &entry));
    }

    #[test]
    fn test_file_pattern_excludes() {
        let file_pats = compile_patterns(&[r"/third_party/"]);
        let func_pats: Vec<Regex> = vec![];
        let entry = mk_entry("bar", "/third_party/lib.cc", "bar", "_Z3barv");
        assert!(should_exclude_function(&file_pats, &func_pats, &entry));
    }

    #[test]
    fn test_file_pattern_no_match() {
        let file_pats = compile_patterns(&[r"/third_party/"]);
        let func_pats: Vec<Regex> = vec![];
        let entry = mk_entry("baz", "/src/baz.cc", "baz", "_Z3bazv");
        assert!(!should_exclude_function(&file_pats, &func_pats, &entry));
    }

    #[test]
    fn test_function_name_excludes() {
        let file_pats: Vec<Regex> = vec![];
        let func_pats = compile_patterns(&[r"^std::"]);
        let entry = mk_entry(
            "std::string::size",
            "/usr/include/string",
            "std::string::size",
            "_ZNSt6string4sizeEv",
        );
        assert!(should_exclude_function(&file_pats, &func_pats, &entry));
    }

    #[test]
    fn test_raw_function_name_excludes() {
        let file_pats: Vec<Regex> = vec![];
        let func_pats = compile_patterns(&[r"__sanitizer"]);
        let entry = mk_entry(
            "sanitizer_init",
            "/src/init.cc",
            "sanitizer_init",
            "__sanitizer_cov_init",
        );
        assert!(should_exclude_function(&file_pats, &func_pats, &entry));
    }

    #[test]
    fn test_empty_source_file_not_excluded() {
        let file_pats = compile_patterns(&[r"/third_party/"]);
        let func_pats: Vec<Regex> = vec![];
        let entry = mk_entry("foo", "", "foo", "_Z3foov");
        assert!(!should_exclude_function(&file_pats, &func_pats, &entry));
    }

    #[test]
    fn test_empty_function_name_not_excluded() {
        let file_pats: Vec<Regex> = vec![];
        let func_pats = compile_patterns(&[r"^std::"]);
        let entry = mk_entry("", "/src/foo.cc", "", "");
        assert!(!should_exclude_function(&file_pats, &func_pats, &entry));
    }

    #[test]
    fn test_profile_excluded_by_fuzzer_source() {
        let file_pats = compile_patterns(&[r"/excluded/"]);
        let func_pats: Vec<Regex> = vec![];
        let profile = ProfileInput {
            profile_id: "test".to_string(),
            fuzzer_source_file: "/excluded/fuzzer.cc".to_string(),
            all_class_functions: vec![
                mk_entry("fn1", "/src/a.cc", "fn1", "_Z3fn1v"),
            ],
            all_class_constructors: vec![],
        };
        let result = filter_profile(&file_pats, &func_pats, &profile);
        assert!(result.excluded);
        assert!(result.excluded_functions.is_none());
        assert!(result.excluded_constructors.is_none());
    }

    #[test]
    fn test_profile_partial_exclusion() {
        let file_pats: Vec<Regex> = vec![];
        let func_pats = compile_patterns(&[r"^std::"]);
        let profile = ProfileInput {
            profile_id: "test".to_string(),
            fuzzer_source_file: "/src/fuzzer.cc".to_string(),
            all_class_functions: vec![
                mk_entry("my_func", "/src/a.cc", "my_func", "_Z7my_funcv"),
                mk_entry("std::vector::push_back", "/usr/include/vector",
                    "std::vector::push_back", "_ZNSt6vectorIiSaIiEE9push_backEOi"),
                mk_entry("my_other", "/src/b.cc", "my_other", "_Z8my_otherv"),
            ],
            all_class_constructors: vec![],
        };
        let result = filter_profile(&file_pats, &func_pats, &profile);
        assert!(!result.excluded);
        let excluded = result.excluded_functions.unwrap();
        assert_eq!(excluded.len(), 1);
        assert_eq!(excluded[0], "std::vector::push_back");
    }

    #[test]
    fn test_multiple_patterns_any_match() {
        let file_pats: Vec<Regex> = vec![];
        let func_pats = compile_patterns(&[r"^std::", r"^__cxx", r"^llvm::"]);
        let e1 = mk_entry("f1", "/src/a.cc", "std::foo", "_Z3foov");
        let e2 = mk_entry("f2", "/src/a.cc", "__cxx_bar", "_Z3barv");
        let e3 = mk_entry("f3", "/src/a.cc", "llvm::baz", "_Z3bazv");
        let e4 = mk_entry("f4", "/src/a.cc", "my_func", "_Z7my_funcv");
        assert!(should_exclude_function(&file_pats, &func_pats, &e1));
        assert!(should_exclude_function(&file_pats, &func_pats, &e2));
        assert!(should_exclude_function(&file_pats, &func_pats, &e3));
        assert!(!should_exclude_function(&file_pats, &func_pats, &e4));
    }

    #[test]
    fn test_end_to_end_json_round_trip() {
        let input_json = r#"{
            "schema_version": 1,
            "file_exclude_patterns": ["/third_party/"],
            "function_exclude_patterns": ["^std::"],
            "profiles": [
                {
                    "profile_id": "fuzzer1",
                    "fuzzer_source_file": "/src/fuzzer1.cc",
                    "all_class_functions": [
                        {
                            "key": "my_func",
                            "function_source_file": "/src/a.cc",
                            "function_name": "my_func",
                            "raw_function_name": "_Z7my_funcv"
                        },
                        {
                            "key": "std::string::size",
                            "function_source_file": "/usr/include/string",
                            "function_name": "std::string::size",
                            "raw_function_name": "_ZNSt6string4sizeEv"
                        }
                    ],
                    "all_class_constructors": []
                },
                {
                    "profile_id": "excluded_fuzzer",
                    "fuzzer_source_file": "/third_party/fuzzer.cc",
                    "all_class_functions": [],
                    "all_class_constructors": []
                }
            ]
        }"#;

        let input: Input = serde_json::from_str(input_json).unwrap();
        let file_pats: Vec<Regex> = input
            .file_exclude_patterns
            .iter()
            .map(|p| Regex::new(p).unwrap())
            .collect();
        let func_pats: Vec<Regex> = input
            .function_exclude_patterns
            .iter()
            .map(|p| Regex::new(p).unwrap())
            .collect();

        let results: Vec<ProfileOutput> = input
            .profiles
            .iter()
            .map(|p| filter_profile(&file_pats, &func_pats, p))
            .collect();

        // fuzzer1: not excluded, but std::string::size should be excluded
        assert!(!results[0].excluded);
        let excl = results[0].excluded_functions.as_ref().unwrap();
        assert_eq!(excl.len(), 1);
        assert_eq!(excl[0], "std::string::size");

        // excluded_fuzzer: entirely excluded
        assert!(results[1].excluded);
    }

    #[test]
    fn test_compile_input_patterns_rejects_invalid_regex() {
        let err = compile_input_patterns(&["(".to_string()], "file").unwrap_err();
        assert!(err.contains("Invalid file exclude pattern"));
    }
}
