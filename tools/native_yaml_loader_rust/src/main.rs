use std::fs::File;
use std::io::{self, Read, Write};

use serde_json::Number;
use serde_json::Value as JsonValue;

fn is_truthy(value: &JsonValue) -> bool {
    match value {
        JsonValue::Null => false,
        JsonValue::Bool(v) => *v,
        JsonValue::Number(v) => {
            if let Some(i) = v.as_i64() {
                i != 0
            } else if let Some(u) = v.as_u64() {
                u != 0
            } else if let Some(f) = v.as_f64() {
                f != 0.0
            } else {
                false
            }
        }
        JsonValue::String(v) => !v.is_empty(),
        JsonValue::Array(v) => !v.is_empty(),
        JsonValue::Object(v) => !v.is_empty(),
    }
}

fn parse_pyyaml_bool(value: &str) -> Option<JsonValue> {
    match value {
        "yes" | "Yes" | "YES" | "on" | "On" | "ON" | "true" | "True" | "TRUE" => {
            Some(JsonValue::Bool(true))
        }
        "no" | "No" | "NO" | "off" | "Off" | "OFF" | "false" | "False" | "FALSE" => {
            Some(JsonValue::Bool(false))
        }
        _ => None,
    }
}

fn validate_underscore_separated_digits(
    value: &str,
    digit_predicate: impl Fn(char) -> bool,
) -> bool {
    if value.is_empty() {
        return false;
    }
    let mut previous_underscore = true;
    let mut seen_digit = false;
    for ch in value.chars() {
        if ch == '_' {
            if previous_underscore {
                return false;
            }
            previous_underscore = true;
            continue;
        }
        if !digit_predicate(ch) {
            return false;
        }
        previous_underscore = false;
        seen_digit = true;
    }
    seen_digit && !previous_underscore
}

fn is_digits_with_underscores(value: &str) -> bool {
    validate_underscore_separated_digits(value, |ch| ch.is_ascii_digit())
}

fn is_octal_digits_with_underscores(value: &str) -> bool {
    validate_underscore_separated_digits(value, |ch| ('0'..='7').contains(&ch))
}

fn parse_pyyaml_int(value: &str) -> Option<JsonValue> {
    if value.is_empty() {
        return None;
    }
    let (negative, body) = if let Some(rest) = value.strip_prefix('+') {
        (false, rest)
    } else if let Some(rest) = value.strip_prefix('-') {
        (true, rest)
    } else {
        (false, value)
    };
    if body.is_empty() {
        return None;
    }

    let (base, digits) = if let Some(rest) = body.strip_prefix("0x").or(body.strip_prefix("0X")) {
        (16, rest)
    } else if let Some(rest) = body.strip_prefix("0b").or(body.strip_prefix("0B")) {
        (2, rest)
    } else if body.len() > 1 && body.starts_with('0') {
        if !is_octal_digits_with_underscores(body) {
            return None;
        }
        (8, body)
    } else {
        if !is_digits_with_underscores(body) {
            return None;
        }
        (10, body)
    };

    if digits.is_empty() {
        return None;
    }
    let normalized_digits = digits.replace('_', "");
    if normalized_digits.is_empty() {
        return None;
    }

    if negative {
        let parsed = u64::from_str_radix(&normalized_digits, base).ok()?;
        let i64_limit_plus_one = (i64::MAX as u64) + 1;
        if parsed > i64_limit_plus_one {
            return None;
        }
        if parsed == i64_limit_plus_one {
            return Some(JsonValue::Number(Number::from(i64::MIN)));
        }
        let value = -(parsed as i64);
        return Some(JsonValue::Number(Number::from(value)));
    }

    if let Ok(parsed) = i64::from_str_radix(&normalized_digits, base) {
        return Some(JsonValue::Number(Number::from(parsed)));
    }
    let parsed = u64::from_str_radix(&normalized_digits, base).ok()?;
    Some(JsonValue::Number(Number::from(parsed)))
}

fn parse_pyyaml_scalar(value: &str) -> Option<JsonValue> {
    parse_pyyaml_bool(value).or_else(|| parse_pyyaml_int(value))
}

fn normalize_yaml(value: JsonValue) -> JsonValue {
    match value {
        JsonValue::Array(values) => JsonValue::Array(values.into_iter().map(normalize_yaml).collect()),
        JsonValue::Object(map) => JsonValue::Object(
            map.into_iter()
                .map(|(key, inner)| (key, normalize_yaml(inner)))
                .collect(),
        ),
        JsonValue::String(text) => parse_pyyaml_scalar(&text).unwrap_or(JsonValue::String(text)),
        other => other,
    }
}

fn load_yaml(path: &str) -> Result<JsonValue, String> {
    let file = File::open(path).map_err(|err| format!("open error: {err}"))?;
    let parsed: JsonValue =
        yaml_serde::from_reader(file).map_err(|err| format!("yaml parse error: {err}"))?;
    Ok(normalize_yaml(parsed))
}

fn extend_python_style(items: &mut Vec<JsonValue>, parsed: JsonValue) -> Result<(), &'static str> {
    match parsed {
        JsonValue::Array(values) => {
            items.extend(values);
            Ok(())
        }
        JsonValue::Object(map) => {
            for (key, _) in map {
                items.push(JsonValue::String(key));
            }
            Ok(())
        }
        JsonValue::String(value) => {
            for ch in value.chars() {
                items.push(JsonValue::String(ch.to_string()));
            }
            Ok(())
        }
        _ => Err("non-iterable truthy yaml payload"),
    }
}

fn handle_profile_mode(path: &str) -> Result<(), String> {
    let mut stdout = io::stdout().lock();
    let value = match load_yaml(path) {
        Ok(parsed) => parsed,
        Err(_) => JsonValue::Null,
    };
    serde_json::to_writer(&mut stdout, &value)
        .map_err(|err| format!("json write error: {err}"))?;
    stdout
        .write_all(b"\n")
        .map_err(|err| format!("stdout write error: {err}"))?;
    Ok(())
}

fn handle_debug_mode(paths: &[JsonValue]) -> Result<(), String> {
    let mut items: Vec<JsonValue> = Vec::with_capacity(paths.len());

    for raw_path in paths {
        let Some(path) = raw_path.as_str() else {
            return Err("paths must be an array of strings".to_string());
        };

        let parsed = match load_yaml(path) {
            Ok(parsed) => parsed,
            Err(err) => {
                eprintln!("failed to parse {path}: {err}");
                continue;
            }
        };

        if !is_truthy(&parsed) {
            continue;
        }

        if let Err(err) = extend_python_style(&mut items, parsed) {
            eprintln!("failed to parse {path}: {err}");
        }
    }

    let mut stdout = io::stdout().lock();
    let out = serde_json::json!({"items": items});
    serde_json::to_writer(&mut stdout, &out).map_err(|err| format!("json write error: {err}"))?;
    stdout
        .write_all(b"\n")
        .map_err(|err| format!("stdout write error: {err}"))?;
    Ok(())
}

fn run() -> Result<i32, String> {
    let mut raw_payload = String::new();
    io::stdin()
        .read_to_string(&mut raw_payload)
        .map_err(|err| format!("stdin read error: {err}"))?;

    let payload: JsonValue = serde_json::from_str(&raw_payload)
        .map_err(|err| format!("invalid input payload: {err}"))?;

    if let Some(path) = payload.get("path").and_then(JsonValue::as_str) {
        if path.trim().is_empty() {
            return Err("invalid path payload".to_string());
        }
        handle_profile_mode(path)?;
        return Ok(0);
    }

    let Some(paths) = payload.get("paths").and_then(JsonValue::as_array) else {
        return Err("expected payload with path or paths".to_string());
    };
    handle_debug_mode(paths)?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::{parse_pyyaml_int, parse_pyyaml_scalar};
    use serde_json::json;

    #[test]
    fn parses_yaml11_bool_tokens() {
        assert_eq!(parse_pyyaml_scalar("NO"), Some(json!(false)));
        assert_eq!(parse_pyyaml_scalar("off"), Some(json!(false)));
        assert_eq!(parse_pyyaml_scalar("YES"), Some(json!(true)));
    }

    #[test]
    fn keeps_quoted_like_strings_unparsed() {
        assert_eq!(parse_pyyaml_scalar("_1"), None);
        assert_eq!(parse_pyyaml_scalar("null"), None);
    }

    #[test]
    fn parses_yaml11_integer_forms() {
        assert_eq!(parse_pyyaml_int("010"), Some(json!(8)));
        assert_eq!(parse_pyyaml_int("0b10"), Some(json!(2)));
        assert_eq!(parse_pyyaml_int("0x10"), Some(json!(16)));
        assert_eq!(
            parse_pyyaml_int("18446744073709551615"),
            Some(json!(18446744073709551615u64))
        );
        assert_eq!(parse_pyyaml_int("09"), None);
    }
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(2);
        }
    }
}
