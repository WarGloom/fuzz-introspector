use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::sync::OnceLock;

use regex::Regex;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Default, Serialize)]
struct OutputPayload {
    covmap: BTreeMap<String, Vec<[i64; 2]>>,
    branch_cov_map: BTreeMap<String, Vec<i64>>,
    coverage_files: Vec<String>,
}

impl OutputPayload {
    fn with_coverage_files(coverage_files: Vec<String>) -> Self {
        Self {
            covmap: BTreeMap::new(),
            branch_cov_map: BTreeMap::new(),
            coverage_files,
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
    SWITCH_LINE_REGEX.get_or_init(|| {
        Regex::new(r".*\|.*\sswitch.*\(.*\)").expect("switch regex must compile")
    })
}

fn case_line_regex() -> &'static Regex {
    static CASE_LINE_REGEX: OnceLock<Regex> = OnceLock::new();
    CASE_LINE_REGEX
        .get_or_init(|| Regex::new(r".*\|.*\scase.*:").expect("case regex must compile"))
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

fn extract_function_name(line: &str) -> String {
    let colon_count = line.chars().filter(|ch| *ch == ':').count();
    let segment = if colon_count == 2 {
        line.split(':').nth(1).unwrap_or(line)
    } else {
        line
    };
    segment
        .chars()
        .filter(|ch| *ch != ' ' && *ch != ':')
        .collect()
}

fn parse_coverage_report(path: &str, out: &mut OutputPayload) -> Result<(), String> {
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
            current_func = extract_function_name(trimmed);
            switch_string.clear();
            switch_line_number = None;
            case_line_numbers.clear();
            // Keep parity with Python loader behavior: latest section wins.
            out.covmap.insert(current_func.clone(), Vec::new());
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

    Ok(())
}

fn render_output_json(payload: &OutputPayload) -> Result<String, String> {
    serde_json::to_string(payload).map_err(|err| format!("failed serializing output payload: {err}"))
}

fn run() -> Result<(), String> {
    let mut raw_input = String::new();
    io::stdin()
        .read_to_string(&mut raw_input)
        .map_err(|err| format!("failed reading stdin: {err}"))?;

    let coverage_reports = parse_coverage_reports(&raw_input)?;

    let mut output = OutputPayload::with_coverage_files(coverage_reports.clone());
    for report_path in &coverage_reports {
        parse_coverage_report(report_path, &mut output)?;
    }

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
