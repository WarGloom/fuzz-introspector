use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::sync::OnceLock;

use rayon::prelude::*;
use regex::Regex;
use serde::Serialize;
use serde_json::Value;

const DEFAULT_MERGE_WINDOW_SIZE: usize = 16;

#[derive(Debug, Default, PartialEq, Eq, Serialize)]
struct OutputPayload {
    covmap: BTreeMap<String, Vec<[i64; 2]>>,
    branch_cov_map: BTreeMap<String, Vec<i64>>,
    coverage_files: Vec<String>,
    function_file_map: BTreeMap<String, String>,
}

impl OutputPayload {
    fn with_coverage_files(coverage_files: Vec<String>) -> Self {
        Self {
            covmap: BTreeMap::new(),
            branch_cov_map: BTreeMap::new(),
            coverage_files,
            function_file_map: BTreeMap::new(),
        }
    }
}

fn parse_coverage_reports(raw_input: &str) -> Result<Vec<String>, String> {
    let payload: Value = serde_json::from_str(raw_input)
        .map_err(|err| format!("failed parsing input payload: {err}"))?;
    let payload_object = payload
        .as_object()
        .ok_or_else(|| "input payload must be a JSON object".to_string())?;
    let coverage_reports_value = payload_object
        .get("coverage_reports")
        .ok_or_else(|| "missing required key: coverage_reports".to_string())?;
    serde_json::from_value(coverage_reports_value.clone())
        .map_err(|err| format!("invalid coverage_reports payload: {err}"))
}

fn switch_line_regex() -> &'static Regex {
    static SWITCH_LINE_REGEX: OnceLock<Regex> = OnceLock::new();
    SWITCH_LINE_REGEX
        .get_or_init(|| Regex::new(r".*\|.*\sswitch.*\(.*\)").expect("switch regex must compile"))
}

fn case_line_regex() -> &'static Regex {
    static CASE_LINE_REGEX: OnceLock<Regex> = OnceLock::new();
    CASE_LINE_REGEX.get_or_init(|| Regex::new(r".*\|.*\scase.*:").expect("case regex must compile"))
}

fn branch_line_regex() -> &'static Regex {
    static BRANCH_LINE_REGEX: OnceLock<Regex> = OnceLock::new();
    BRANCH_LINE_REGEX.get_or_init(|| {
        Regex::new(
            r"Branch\s*\(\s*(\d+)\s*:\s*(\d+)\s*\):\s*\[True:\s*([^,\]]+),\s*False:\s*([^\]]+)\]",
        )
        .expect("branch regex must compile")
    })
}

fn extract_hit_count(raw: &str) -> Option<i64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    if trimmed.contains('e') || trimmed.contains('E') {
        let parsed = trimmed.parse::<f64>().ok()?;
        if !parsed.is_finite() {
            return None;
        }
        return Some(parsed as i64);
    }

    let last = trimmed.chars().last()?;
    if last.is_ascii_digit() {
        return trimmed.parse::<i64>().ok();
    }

    let (number_part, multiplier) = match last {
        'k' => (&trimmed[..trimmed.len() - 1], 1_000f64),
        'M' => (&trimmed[..trimmed.len() - 1], 1_000_000f64),
        'G' => (&trimmed[..trimmed.len() - 1], 1_000_000_000f64),
        _ => return None,
    };

    let parsed = number_part.parse::<f64>().ok()?;
    if !parsed.is_finite() {
        return None;
    }
    Some((parsed * multiplier) as i64)
}

fn parse_branch_line(line: &str) -> Option<(i64, i64, i64, i64)> {
    let captures = branch_line_regex().captures(line)?;
    let line_number = captures.get(1)?.as_str().trim().parse::<i64>().ok()?;
    let column_number = captures.get(2)?.as_str().trim().parse::<i64>().ok()?;
    let true_hit = extract_hit_count(captures.get(3)?.as_str())?;
    let false_hit = extract_hit_count(captures.get(4)?.as_str())?;
    Some((line_number, column_number, true_hit, false_hit))
}

fn extract_function_header(line: &str) -> (String, String) {
    let colon_count = line.chars().filter(|ch| *ch == ':').count();
    let (function_segment, source_file) = if colon_count == 2 {
        let mut segments = line.split(':');
        let file_segment = segments.next().unwrap_or("").trim();
        let func_segment = segments.next().unwrap_or(line);
        (func_segment, file_segment)
    } else {
        (line, "")
    };
    let function_name = function_segment
        .chars()
        .filter(|ch| *ch != ' ' && *ch != ':')
        .collect();
    (function_name, source_file.to_string())
}

fn parse_coverage_report(path: &str) -> Result<OutputPayload, String> {
    let mut out = OutputPayload::default();
    let file = File::open(path).map_err(|err| format!("failed to open {path}: {err}"))?;
    let mut reader = BufReader::new(file);
    let mut line_buf: Vec<u8> = Vec::new();

    let mut current_func = String::new();
    let mut switch_string = String::new();
    let mut switch_line_number: Option<i64> = None;
    let mut case_line_numbers: HashSet<i64> = HashSet::new();

    loop {
        line_buf.clear();
        let bytes_read = reader
            .read_until(b'\n', &mut line_buf)
            .map_err(|err| format!("failed reading {path}: {err}"))?;
        if bytes_read == 0 {
            break;
        }

        let line = String::from_utf8_lossy(&line_buf);
        let line = line.trim_end_matches(['\n', '\r']);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if trimmed.ends_with(':') && !trimmed.contains('|') {
            let (function_name, source_file) = extract_function_header(trimmed);
            current_func = function_name;
            switch_string.clear();
            switch_line_number = None;
            case_line_numbers.clear();
            // Keep parity with Python loader behavior: latest section wins.
            out.covmap.insert(current_func.clone(), Vec::new());
            if !source_file.is_empty() {
                out.function_file_map
                    .insert(current_func.clone(), source_file);
            }
            continue;
        }

        if current_func.is_empty() {
            continue;
        }

        if line.contains("Branch") && line.contains("[True:") && line.contains("False:") {
            if let Some((branch_line, branch_col, true_hit, false_hit)) = parse_branch_line(line) {
                if switch_line_number == Some(branch_line) && !switch_string.is_empty() {
                    out.branch_cov_map
                        .insert(switch_string.clone(), vec![true_hit, false_hit]);
                } else if case_line_numbers.contains(&branch_line) && !switch_string.is_empty() {
                    if let Some(existing) = out.branch_cov_map.get_mut(&switch_string) {
                        existing.push(true_hit);
                    } else {
                        out.branch_cov_map
                            .insert(switch_string.clone(), vec![true_hit, false_hit, true_hit]);
                    }
                } else {
                    let branch_key = format!("{current_func}:{branch_line},{branch_col}");
                    out.branch_cov_map
                        .insert(branch_key, vec![true_hit, false_hit]);
                }
            }
        }

        if !line.contains('|') {
            continue;
        }

        let mut parts = line.split('|');
        let Some(line_no_part) = parts.next() else {
            continue;
        };
        let Some(hit_count_part) = parts.next() else {
            continue;
        };
        let source_fragment = parts.next().unwrap_or("");

        let line_no = match line_no_part.trim().parse::<i64>() {
            Ok(value) => value,
            Err(_) => continue,
        };

        if source_fragment.contains("switch")
            && source_fragment.contains('(')
            && source_fragment.contains(')')
            && switch_line_regex().is_match(line)
        {
            if let Some(index) = source_fragment.find("switch") {
                switch_line_number = Some(line_no);
                case_line_numbers.clear();
                let column_number = (index as i64) + 1;
                switch_string = format!("{current_func}:{line_no},{column_number}");
            }
        }

        if !switch_string.is_empty()
            && source_fragment.contains("case")
            && source_fragment.contains(':')
            && case_line_regex().is_match(line)
        {
            case_line_numbers.insert(line_no);
        }

        let hit_count = match extract_hit_count(hit_count_part) {
            Some(value) => value,
            None => {
                if line.contains(" 0| ") || line.contains("| 0|") {
                    0
                } else {
                    continue;
                }
            }
        };

        if let Some(cov_entries) = out.covmap.get_mut(current_func.as_str()) {
            cov_entries.push([line_no, hit_count]);
        } else {
            out.covmap
                .entry(current_func.clone())
                .or_default()
                .push([line_no, hit_count]);
        }
    }

    Ok(out)
}

fn render_output_json(payload: &OutputPayload) -> Result<String, String> {
    serde_json::to_string(payload)
        .map_err(|err| format!("failed serializing output payload: {err}"))
}

fn merge_output_payload(base: &mut OutputPayload, partial: OutputPayload) {
    base.covmap.extend(partial.covmap);
    base.branch_cov_map.extend(partial.branch_cov_map);
    base.function_file_map.extend(partial.function_file_map);
}

fn parse_and_merge_reports_windowed(
    coverage_reports: &[String],
    merge_window_size: usize,
) -> Result<OutputPayload, String> {
    let bounded_window_size = merge_window_size.max(1);
    let mut output = OutputPayload::with_coverage_files(coverage_reports.to_vec());

    for report_window in coverage_reports.chunks(bounded_window_size) {
        let partial_outputs: Vec<Result<OutputPayload, String>> = report_window
            .par_iter()
            .map(|path| parse_coverage_report(path))
            .collect();

        for partial in partial_outputs {
            merge_output_payload(&mut output, partial?);
        }
    }

    Ok(output)
}

fn run() -> Result<(), String> {
    let mut raw_input = String::new();
    io::stdin()
        .read_to_string(&mut raw_input)
        .map_err(|err| format!("failed reading stdin: {err}"))?;

    let coverage_reports = parse_coverage_reports(&raw_input)?;

    let output = parse_and_merge_reports_windowed(&coverage_reports, DEFAULT_MERGE_WINDOW_SIZE)?;

    let json_output = render_output_json(&output)?;
    io::stdout()
        .write_all(json_output.as_bytes())
        .map_err(|err| format!("failed writing output payload: {err}"))?;
    io::stdout()
        .write_all(b"\n")
        .map_err(|err| format!("failed writing output newline: {err}"))?;
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        let _ = writeln!(io::stderr(), "{err}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn write_temp_report(contents: &str) -> Result<String, String> {
        let mut path = env::temp_dir();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| format!("failed to calculate unix timestamp: {err}"))?
            .as_nanos();
        path.push(format!(
            "native_llvm_cov_loader_rust_test_{}_{}.txt",
            std::process::id(),
            now
        ));
        fs::write(&path, contents)
            .map_err(|err| format!("failed writing temp report {}: {err}", path.display()))?;
        Ok(path_to_string(path))
    }

    fn path_to_string(path: PathBuf) -> String {
        path.to_string_lossy().into_owned()
    }

    fn delete_temp_reports(paths: &[String]) {
        for path in paths {
            let _ = fs::remove_file(path);
        }
    }

    #[test]
    fn merge_is_deterministic_across_window_sizes() -> Result<(), String> {
        let report_one = write_temp_report(
            "target:\n1| 1| switch(a)\nBranch (1:1): [True: 1, False: 0]\n2| 1| case 0:\nBranch (2:1): [True: 3, False: 0]\n",
        )?;
        let report_two = write_temp_report(
            "target:\n1| 2| switch(a)\nBranch (1:1): [True: 2, False: 0]\n2| 1| case 0:\nBranch (2:1): [True: 4, False: 0]\n",
        )?;
        let report_three = write_temp_report(
            "target:\n1| 3| switch(a)\nBranch (1:1): [True: 5, False: 1]\n2| 1| case 0:\nBranch (2:1): [True: 9, False: 0]\n",
        )?;
        let reports = vec![report_one, report_two, report_three];

        let merged_single = parse_and_merge_reports_windowed(&reports, 1)?;
        let merged_windowed = parse_and_merge_reports_windowed(&reports, 2)?;
        let merged_all = parse_and_merge_reports_windowed(&reports, 32)?;

        assert_eq!(merged_single, merged_windowed);
        assert_eq!(merged_single, merged_all);
        assert_eq!(
            merged_single.covmap.get("target"),
            Some(&vec![[1, 3], [2, 1]])
        );
        assert_eq!(
            merged_single.branch_cov_map.get("target:1,2"),
            Some(&vec![5, 1, 9])
        );

        delete_temp_reports(&reports);
        Ok(())
    }

    #[test]
    fn duplicate_function_sections_keep_latest_payload() -> Result<(), String> {
        let report = write_temp_report(
            "src/dup.cc:dup:\n1| 9| old\n\nsrc/dup.cc:dup:\n1| 5| switch(x)\nBranch (1:3): [True: 7, False: 2]\n2| 1| case 1:\nBranch (2:3): [True: 4, False: 0]\n",
        )?;

        let parsed = parse_coverage_report(&report)?;

        assert_eq!(parsed.covmap.get("dup"), Some(&vec![[1, 5], [2, 1]]));
        assert_eq!(
            parsed.function_file_map.get("dup"),
            Some(&"src/dup.cc".to_string())
        );
        assert_eq!(parsed.branch_cov_map.get("dup:1,2"), Some(&vec![7, 2, 4]));

        delete_temp_reports(&[report]);
        Ok(())
    }

    #[test]
    fn filename_qualified_headers_emit_function_file_map() -> Result<(), String> {
        let report = write_temp_report(
            "src/fuzzer.cpp:LLVMFuzzerTestOneInput:\n7| 3| return 0;\n8| 0| return 1;\n",
        )?;

        let parsed = parse_coverage_report(&report)?;

        assert_eq!(
            parsed.covmap.get("LLVMFuzzerTestOneInput"),
            Some(&vec![[7, 3], [8, 0]])
        );
        assert_eq!(
            parsed.function_file_map.get("LLVMFuzzerTestOneInput"),
            Some(&"src/fuzzer.cpp".to_string())
        );

        delete_temp_reports(&[report]);
        Ok(())
    }
}
