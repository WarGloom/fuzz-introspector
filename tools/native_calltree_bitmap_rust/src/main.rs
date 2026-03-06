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

//! Native calltree bitmap renderer for fuzz-introspector.
//!
//! Reads a JSON payload from stdin describing one or more bitmap
//! rendering jobs (each with a list of color strings and an output path),
//! renders them as PNG images in parallel using rayon, and writes a
//! JSON status report to stdout.
//!
//! This replaces the matplotlib-based bitmap rendering in
//! `html_helpers.py::_create_horisontal_calltree_image_impl` which is
//! slow due to Figure/Axes overhead and deepcopy in tight_layout.
//!
//! Protocol:
//!   - Input:  JSON on stdin  (see `Input` struct)
//!   - Output: JSON on stdout (see `Output` struct)
//!
//! Activation:
//!   - `FI_CALLTREE_BITMAP_BACKEND=rust` (or `FI_NATIVE_BACKENDS=rust`)
//!   - Binary located via `FI_CALLTREE_BITMAP_RUST_BIN` or `PATH` lookup.

use std::io::{self, Read, Write};

use log::info;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Input types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct Input {
    schema_version: u32,
    /// Image width in pixels (default 1500).
    #[serde(default = "default_width")]
    width: u32,
    /// Image height in pixels (default 250).
    #[serde(default = "default_height")]
    height: u32,
    /// List of bitmap jobs to render in parallel.
    jobs: Vec<BitmapJob>,
}

#[derive(Debug, Deserialize)]
struct BitmapJob {
    /// Unique job identifier (e.g. profile index).
    job_id: String,
    /// Output file path for the PNG.
    output_path: String,
    /// List of color names: "red", "gold", "yellow", "greenyellow", "lawngreen".
    color_list: Vec<String>,
}

fn default_width() -> u32 {
    1500
}

fn default_height() -> u32 {
    250
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct Output {
    status: String,
    results: Vec<JobResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct JobResult {
    job_id: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

// ---------------------------------------------------------------------------
// Color mapping
// ---------------------------------------------------------------------------

/// Map a matplotlib-compatible color name to an RGB triple.
fn color_name_to_rgb(name: &str) -> [u8; 3] {
    match name {
        "red" => [0xff, 0x00, 0x00],
        "gold" => [0xff, 0xd7, 0x00],
        "yellow" => [0xff, 0xff, 0x00],
        "greenyellow" => [0xad, 0xff, 0x2f],
        "lawngreen" => [0x7c, 0xfc, 0x00],
        _ => [0xff, 0x00, 0x00], // default to red for unknown
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn render_bitmap(job: &BitmapJob, width: u32, height: u32) -> JobResult {
    match render_bitmap_inner(job, width, height) {
        Ok(()) => JobResult {
            job_id: job.job_id.clone(),
            status: "ok".to_string(),
            error: None,
        },
        Err(e) => JobResult {
            job_id: job.job_id.clone(),
            status: "error".to_string(),
            error: Some(e.to_string()),
        },
    }
}

fn render_bitmap_inner(
    job: &BitmapJob,
    width: u32,
    height: u32,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let colors: Vec<&str> = if job.color_list.is_empty() {
        vec!["red"]
    } else {
        job.color_list.iter().map(|s| s.as_str()).collect()
    };

    let n = colors.len();
    let ppn = width as f64 / n as f64;

    let mut img = image::RgbImage::from_pixel(width, height, image::Rgb([255, 255, 255]));

    for (i, color_name) in colors.iter().enumerate() {
        let x_start = (i as f64 * ppn).round() as u32;
        let x_end = ((i + 1) as f64 * ppn).round() as u32;
        let rgb = color_name_to_rgb(color_name);
        let pixel = image::Rgb(rgb);
        for x in x_start..x_end.min(width) {
            for y in 0..height {
                img.put_pixel(x, y, pixel);
            }
        }
    }

    // Create parent directories if needed.
    if let Some(parent) = std::path::Path::new(&job.output_path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    img.save(&job.output_path)?;
    info!("Rendered {} ({} nodes -> {})", job.job_id, n, job.output_path);
    Ok(())
}

// ---------------------------------------------------------------------------
// Error helper
// ---------------------------------------------------------------------------

fn write_error(msg: String) -> ! {
    let out = Output {
        status: "error".to_string(),
        results: vec![],
        error: Some(msg),
    };
    let _ = writeln!(io::stdout(), "{}", serde_json::to_string(&out).unwrap());
    std::process::exit(1);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    env_logger::init();
    info!("native_calltree_bitmap_rust starting");

    // Read all of stdin.
    let mut raw = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut raw) {
        write_error(format!("Failed to read stdin: {e}"));
    }

    // Parse JSON input.
    let input: Input = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            write_error(format!("JSON parse error: {e}"));
        }
    };

    // Validate schema version.
    if input.schema_version != 1 {
        write_error(format!(
            "Unsupported schema_version: {}",
            input.schema_version
        ));
    }

    info!(
        "Processing {} bitmap jobs ({}x{})",
        input.jobs.len(),
        input.width,
        input.height,
    );

    // Process jobs in parallel.
    let results: Vec<JobResult> = input
        .jobs
        .par_iter()
        .map(|job| render_bitmap(job, input.width, input.height))
        .collect();

    let all_ok = results.iter().all(|r| r.status == "ok");
    let output = Output {
        status: if all_ok {
            "success".to_string()
        } else {
            "partial".to_string()
        },
        results,
        error: None,
    };

    let json = match serde_json::to_string(&output) {
        Ok(s) => s,
        Err(e) => {
            write_error(format!("JSON serialization error: {e}"));
        }
    };

    let stdout = io::stdout();
    let mut handle = stdout.lock();
    if let Err(e) = writeln!(handle, "{json}") {
        eprintln!("Failed to write output: {e}");
        std::process::exit(1);
    }

    info!("native_calltree_bitmap_rust done");
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// Return a unique temp file path incorporating the test name.
    fn temp_png(label: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let id = std::process::id();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("fi_bitmap_test_{label}_{id}_{ts}.png"));
        p
    }

    #[test]
    fn test_color_name_to_rgb() {
        assert_eq!(color_name_to_rgb("red"), [0xff, 0x00, 0x00]);
        assert_eq!(color_name_to_rgb("gold"), [0xff, 0xd7, 0x00]);
        assert_eq!(color_name_to_rgb("yellow"), [0xff, 0xff, 0x00]);
        assert_eq!(color_name_to_rgb("greenyellow"), [0xad, 0xff, 0x2f]);
        assert_eq!(color_name_to_rgb("lawngreen"), [0x7c, 0xfc, 0x00]);
        // Unknown color defaults to red.
        assert_eq!(color_name_to_rgb("magenta"), [0xff, 0x00, 0x00]);
        assert_eq!(color_name_to_rgb(""), [0xff, 0x00, 0x00]);
    }

    #[test]
    fn test_render_single_color() {
        let path = temp_png("single");
        let job = BitmapJob {
            job_id: "single".to_string(),
            output_path: path.to_str().unwrap().to_string(),
            color_list: vec!["lawngreen".to_string()],
        };
        let result = render_bitmap(&job, 100, 50);
        assert_eq!(result.status, "ok");
        assert!(result.error.is_none());
        let meta = fs::metadata(&path).unwrap();
        assert!(meta.len() > 0);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_render_mixed_colors() {
        let path = temp_png("mixed");
        let job = BitmapJob {
            job_id: "mixed".to_string(),
            output_path: path.to_str().unwrap().to_string(),
            color_list: vec![
                "red".to_string(),
                "red".to_string(),
                "gold".to_string(),
                "lawngreen".to_string(),
            ],
        };
        let result = render_bitmap(&job, 200, 60);
        assert_eq!(result.status, "ok");
        assert!(result.error.is_none());
        let meta = fs::metadata(&path).unwrap();
        assert!(meta.len() > 0);

        // Verify that the PNG can be loaded and has the right dimensions.
        let img = image::open(&path).unwrap().to_rgb8();
        assert_eq!(img.width(), 200);
        assert_eq!(img.height(), 60);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_render_empty_color_list() {
        let path = temp_png("empty");
        let job = BitmapJob {
            job_id: "empty".to_string(),
            output_path: path.to_str().unwrap().to_string(),
            color_list: vec![],
        };
        let result = render_bitmap(&job, 100, 40);
        assert_eq!(result.status, "ok");
        assert!(result.error.is_none());
        let meta = fs::metadata(&path).unwrap();
        assert!(meta.len() > 0);

        // Empty list defaults to red; verify first pixel is red.
        let img = image::open(&path).unwrap().to_rgb8();
        assert_eq!(*img.get_pixel(0, 0), image::Rgb([0xff, 0x00, 0x00]));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_render_large_bitmap() {
        let path = temp_png("large");
        let colors: Vec<String> = (0..10_000)
            .map(|i| {
                match i % 5 {
                    0 => "red",
                    1 => "gold",
                    2 => "yellow",
                    3 => "greenyellow",
                    _ => "lawngreen",
                }
                .to_string()
            })
            .collect();

        let job = BitmapJob {
            job_id: "large".to_string(),
            output_path: path.to_str().unwrap().to_string(),
            color_list: colors,
        };

        let start = std::time::Instant::now();
        let result = render_bitmap(&job, 1500, 250);
        let elapsed = start.elapsed();

        assert_eq!(result.status, "ok");
        assert!(result.error.is_none());
        let meta = fs::metadata(&path).unwrap();
        assert!(meta.len() > 0);
        // Should complete in well under 5 seconds.
        assert!(
            elapsed.as_secs() < 5,
            "Render took too long: {:?}",
            elapsed
        );

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_full_pipeline_json() {
        let path1 = temp_png("pipeline_a");
        let path2 = temp_png("pipeline_b");
        let input_json = format!(
            r#"{{
                "schema_version": 1,
                "width": 120,
                "height": 30,
                "jobs": [
                    {{
                        "job_id": "j1",
                        "output_path": "{}",
                        "color_list": ["red", "gold", "lawngreen"]
                    }},
                    {{
                        "job_id": "j2",
                        "output_path": "{}",
                        "color_list": ["yellow"]
                    }}
                ]
            }}"#,
            path1.to_str().unwrap().replace('\\', "\\\\"),
            path2.to_str().unwrap().replace('\\', "\\\\"),
        );

        let input: Input = serde_json::from_str(&input_json).unwrap();
        assert_eq!(input.schema_version, 1);
        assert_eq!(input.width, 120);
        assert_eq!(input.height, 30);
        assert_eq!(input.jobs.len(), 2);

        let results: Vec<JobResult> = input
            .jobs
            .par_iter()
            .map(|job| render_bitmap(job, input.width, input.height))
            .collect();

        let all_ok = results.iter().all(|r| r.status == "ok");
        let output = Output {
            status: if all_ok {
                "success".to_string()
            } else {
                "partial".to_string()
            },
            results,
            error: None,
        };

        assert_eq!(output.status, "success");
        assert_eq!(output.results.len(), 2);
        assert_eq!(output.results[0].status, "ok");
        assert_eq!(output.results[1].status, "ok");

        // Verify both PNGs exist.
        assert!(fs::metadata(&path1).unwrap().len() > 0);
        assert!(fs::metadata(&path2).unwrap().len() > 0);

        // Verify serialization round-trips cleanly.
        let json_out = serde_json::to_string(&output).unwrap();
        assert!(json_out.contains("\"status\":\"success\""));

        let _ = fs::remove_file(&path1);
        let _ = fs::remove_file(&path2);
    }

    #[test]
    fn test_invalid_schema_version() {
        let input_json = r#"{
            "schema_version": 99,
            "jobs": []
        }"#;
        let input: Input = serde_json::from_str(input_json).unwrap();
        assert_eq!(input.schema_version, 99);
        // The main() function would reject this, but we verify parsing works
        // and the version field is correctly captured for validation.
        assert_ne!(input.schema_version, 1);
    }

    #[test]
    fn test_default_dimensions() {
        let input_json = r#"{
            "schema_version": 1,
            "jobs": []
        }"#;
        let input: Input = serde_json::from_str(input_json).unwrap();
        assert_eq!(input.width, 1500);
        assert_eq!(input.height, 250);
    }
}
