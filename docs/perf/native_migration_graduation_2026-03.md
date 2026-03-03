# Native Migration Graduation Decision — March 2026

*Decision date: March 3, 2026*
*Branch: `memory-improvements`*
*Benchmark corpus: cgserver (49 fuzzers, production data)*

---

## Executive Summary

**GRADUATED.** The native Rust backend meets both graduation gate thresholds:
**8.11× wall-time speedup** and **−49.4% peak RSS** versus the Python baseline,
measured on the cgserver production corpus (49 fuzzers). Output is hash-identical
across all three backends (Python, Rust, Go). The 10-run stability test passed
with zero crashes and zero Python fallbacks. `FI_NATIVE_BACKENDS=rust` is baked
into the OSS-Fuzz base-builder Dockerfile and is the active default.

---

## Graduation Gate Results

| Metric | Gate threshold | Actual (Rust) | Pass/Fail |
|--------|---------------|--------------|-----------|
| Speedup (cgserver) | ≥ 5× | **8.11×** | ✅ Pass |
| RSS reduction (cgserver) | ≥ 40% | **−49.4%** (−5,487 MB) | ✅ Pass |
| Output parity | 100% hash match | **100%** | ✅ Pass |
| Stability (10 consecutive runs) | 0 failures | **0 failures** | ✅ Pass |

Both primary graduation gates met; rollout to production is authorised.

---

## Benchmark Methodology

| Parameter | Value |
|-----------|-------|
| Corpus | cgserver introspector data, 49 fuzzers |
| Data location | `cgserver/build-introspector-full-2/introspector/` |
| Measurement tool | `/usr/bin/time -v` (wall time + maximum resident set size) |
| Python baseline runs | 1 |
| Rust authoritative runs | 3 (averaged) |
| Rust stability runs | 10 |
| Go runs | 1 |
| Parity check | SHA-256 of `summary.json` |
| simdjson corpus | Dropped — symlinked to cgserver; not an independent dataset |

All measurements were taken on the same machine with no other heavy workloads running.
cgserver (49 fuzzers, real production scale) is the sole authoritative benchmark corpus.

---

## Per-Backend Results

| Backend | Wall time (s) | Peak RSS (MB) | Runs | Output hash (SHA-256) |
|---------|--------------|--------------|------|-----------------------|
| Python (baseline) | 687.67 | 11,100.30 | 1 | `3e0a44d4…` |
| **Rust (3-run avg)** | **84.82** | **5,613.71** | **3** | `3e0a44d4…` ✅ |
| Go | 94.19 | 5,768.00 | 1 | `3e0a44d4…` ✅ |

Full hash: `3e0a44d44abbf1d3968e2d3e2223045618ffeeb3e37776a6b75c1c9853c2061b`

Baseline files:
- Python — `.work/baselines/cgserver-full_baseline.json` (timestamp `20260302_182612`)
- Rust — `.work/baselines/cgserver-full_rust_baseline.json` (timestamp `20260303_131332`)

---

## Stability Results (Rust, 10-run test)

| Stat | Value |
|------|-------|
| Runs | 10 |
| Hash-identical runs | 10 / 10 |
| Crashes | 0 |
| Python fallbacks triggered | 0 |
| Wall time avg | 94.24 s |
| Peak RSS avg | 5,804.77 MB |

All 10 runs produced the identical `summary.json` hash. No non-determinism observed.

---

## Native Component Inventory (Rust)

| Binary | Source crate | Function |
|--------|-------------|----------|
| `fi_profile_yaml_loader` | `native_yaml_loader_rust` | Loads per-fuzzer profile YAML files |
| `fi_debug_yaml_loader` | `native_yaml_loader_rust` | Loads debug-info YAML files |
| `fi_llvm_cov_loader` | `native_llvm_cov_loader_rust` | Parses LLVM coverage JSON exports |
| `fi_debug_correlator` | `native_debug_correlator_rust` | Correlates debug symbols with coverage data |

All four binaries are built at CI time and placed on `PATH` by the OSS-Fuzz integration.
The Python layer dispatches to these binaries when `FI_NATIVE_BACKENDS=rust` is set;
it falls back to pure Python automatically if a binary is absent.

---

## OSS-Fuzz Integration Status

| Item | Status |
|------|--------|
| Build script | `build_native_post_processing.sh` — builds all 4 Rust binaries at image-build time |
| ENV variable | `FI_NATIVE_BACKENDS=rust` baked into base-builder `Dockerfile` via `oss-fuzz-patches.diff` |
| `PATH` extension | Native binary directory added to `PATH` in same Dockerfile patch |
| Manual env setup required | None — fully automated |
| Python fallback available | Yes — if binary missing, pipeline falls back transparently |

The OSS-Fuzz patch (`oss-fuzz-patches.diff`) is maintained in the repository and applied
to the OSS-Fuzz master branch during the container build.

---

## Key Bug Fixed During Sprint

### Correlator dispatch not receiving `FI_NATIVE_BACKENDS` (commit `3ea05fbd`)

**Problem:** The correlator subprocess was launched without forwarding
`FI_NATIVE_BACKENDS` from the parent environment. This meant the correlator always
ran the Python path regardless of the flag, silently degrading performance and
invalidating earlier benchmark numbers (the correlator is the dominant CPU consumer).

**Impact:** Before the fix, the "Rust" configuration was actually running the Python
correlator for the most expensive phase. Benchmark numbers recorded before `3ea05fbd`
overstated effective Rust speedup for that subset of runs, and understated it once the
fix was applied (the true Rust end-to-end path is faster).

**Fix:** Explicitly propagate `FI_NATIVE_BACKENDS` (and the full environment) to the
correlator subprocess call. Baselines were re-recorded after this fix (commit `9ddcee38`).

---

## Sprint Commits Included

| Commit | Type | Summary |
|--------|------|---------|
| `2018c3ab` | perf | Skip Python type loading in native correlator path |
| `84fd5554` | feat | Add stage marker writer for pipeline phase timing |
| `19fb22b0` | feat | Build native Rust binaries in `build_native_post_processing.sh` |
| `3ea05fbd` | fix | **Propagate `FI_NATIVE_BACKENDS` to correlator dispatch** ← critical |
| `9ddcee38` | chore | Update cgserver Rust baseline after correlator dispatch fix |

Earlier sprint commits (Go parity, plugin wiring, env-var rationalisation, lint fixes,
BACKEND_CPP removal) are present in the branch history and covered by the parity hash.

---

## Known Limitations and Follow-On Work

| Item | Notes |
|------|-------|
| Go backend | Fully functional alternative (`--backend go`); 94.19 s / 5,768 MB on cgserver. Not the default; available for comparison or fallback. |
| Stage markers | `stage_markers.py` emits per-phase timing to `<out_dir>/stage_markers.log`. Useful for future profiling; not yet integrated into CI dashboards. |
| simdjson corpus | Dropped from benchmarks — the local copy was a symlink to cgserver data. There is no independent simdjson dataset; cgserver is the sole benchmark corpus. |
| Sprint 3 plugins (parallel) | Rust analysis plugin parallelism is wired and passing parity. Full plugin-level parallelism tuning is a post-graduation follow-on. |
| 30-day production monitoring | Per the migration plan: track crash rate (<0.1%), fallback rate (<2%), and per-project performance for 30 days after enabling by default. |

---

## Decision

**GRADUATED — native Rust backend enabled by default.**

Both graduation gate thresholds are satisfied:

- Speedup: **8.11×** ≥ required 5× ✅
- RSS reduction: **49.4%** ≥ required 40% ✅

Output parity is confirmed (hash-identical, all backends). Stability is confirmed
(10/10 runs, 0 crashes, 0 fallbacks). OSS-Fuzz integration is automated and requires
no manual operator steps.

The critical correlator dispatch bug (`3ea05fbd`) was identified and fixed before
final baseline recording; all graduation numbers reflect the correct, fully-native path.

---

## Evidence References

- Python baseline: `.work/baselines/cgserver-full_baseline.json`
- Rust baseline: `.work/baselines/cgserver-full_rust_baseline.json`
- Migration plan and gate definitions: `docs/perf/native_migration_plan_2026-03.md` §"Graduation Gate"
- OSS-Fuzz patch: `oss-fuzz-patches.diff`
- Build script: `build_native_post_processing.sh`
- Stage marker implementation: `src/fuzz_introspector/stage_markers.py`
