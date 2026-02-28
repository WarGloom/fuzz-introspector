[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/ossf/fuzz-introspector/badge)](https://api.securityscorecards.dev/projects/github.com/ossf/fuzz-introspector)

# Fuzz introspector

Fuzz introspector is a tool to help fuzzer developers to get an understanding of their fuzzer’s performance 
and identify any potential blockers. Fuzz introspector aggregates the fuzzers’ functional data like coverage,
hit frequency, entry points, etc to give the developer a birds eye view of their fuzzer. This helps with 
identifying fuzz bottlenecks and blockers and eventually helps in developing better fuzzers.

Fuzz-introspector aims to improve fuzzing experience of a project by guiding on whether you should:
- introduce new fuzzers to a fuzz harness
- modify existing fuzzers to improve the quality of your harness.

## Indexing OSS-Fuzz projects

[Open Source Fuzzing Introspection](https://introspector.oss-fuzz.com) provides introspection capabilities to [OSS-Fuzz](https://github.com/google/oss-fuzz) projects and is powered by Fuzz Introspector. This page gives macro insights into the fuzzing of open source projects.

On this page you'll see a list of all the projects that are currently analysed by Fuzz Introspector:
- [Table of projects with Fuzz Introspector analysis](https://introspector.oss-fuzz.com/projects-overview)
- Examples, with links in profile to latest Fuzz Introspector analysis:
  - [Liblouis / C](https://introspector.oss-fuzz.com/project-profile?project=liblouis)
  - [htslib / C](https://introspector.oss-fuzz.com/project-profile?project=htslib)
  - [brotli / C++](https://introspector.oss-fuzz.com/project-profile?project=brotli)
  - [idna / python](https://introspector.oss-fuzz.com/project-profile?project=idna)
  - [junrar / java](https://introspector.oss-fuzz.com/project-profile?project=junrar)


## Docs and demonstrations

Fuzz Introspector is build, tested and run with Python3.14. Other versions may
work, but they are not officially supported.

The main Fuzz Introspector documentation is available here: https://fuzz-introspector.readthedocs.io This documentation includes user guides, OSS-Fuzz instructions, tutorials, development docs and more.
Additionally, there is more information:
- [Video demonstration](https://www.youtube.com/watch?v=cheo-liJhuE)
- [List of Case studies](doc/CaseStudies.md)
- [Screenshots](doc/ExampleOutput.md)
- [Feature list](doc/Features.md)
- Try yourself:
  - [Use with OSS-Fuzz](oss_fuzz_integration#build-fuzz-introspector-with-oss-fuzz) (Recommended)
  - [Use without OSS-Fuzz](doc/LocalBuild.md)

## Debug YAML telemetry and tuning

The debug-info YAML loading/correlation pipeline supports `FI_DEBUG_*` tuning
variables:

Not all environment variables are required for normal use. Most users can keep
defaults and only set the minimal correlator variables listed below.

- `FI_DEBUG_PARALLEL` (default: `true`): enable parallel YAML shard loading.
- `FI_DEBUG_MAX_WORKERS` (default: `min(cpu_count, 8)`): worker cap for YAML
  loading.
- `FI_DEBUG_SHARD_FILES` (default: `4`): number of YAML files per shard.
- `FI_DEBUG_SPILL_MB` (default: `0`): in-memory shard spill threshold in MB.
  `0` disables spill-to-disk.
- `FI_DEBUG_MAX_INMEM_MB` (default: `0`): hard in-memory cap for shard
  buffering in MB. `0` disables cap-based spilling.
- `FI_DEBUG_MAX_INFLIGHT_SHARDS` (default: `min(max_workers, 2, shard_count)`):
  maximum concurrent shards in YAML load phase.
- `FI_DEBUG_ADAPTIVE_WORKERS` (default: `false`): enable spill/timing based
  in-flight downshift and recovery.
- `FI_DEBUG_SHARD_STRATEGY` (default: `fixed_count`): strategy for building YAML
  shards.
  Supported: `fixed_count`, `size_balanced`.
- `FI_DEBUG_RSS_SOFT_LIMIT_MB` (default: `0`): if set, temporarily lowers
  in-flight shards when RSS is above this threshold.
- `FI_DEBUG_SPILL_POLICY` (default: `oldest`): choose which shard to spill
  first under memory pressure. Supported: `oldest`, `largest`.
- `FI_DEBUG_STAGE_RSS` (default: `false`): include RSS snapshot in debug-load
  stage telemetry (`rss_mb=...`).
- `FI_DEBUG_PERF_WARN` (default: `true`): emit performance guidance warnings
  for slow or high-memory debug stages.
- `FI_DEBUG_STAGE_WARN_RSS_MB` (default: `0`): warning threshold in MB for
  per-stage RSS. `0` disables RSS threshold warnings.
- `FI_DEBUG_CORRELATE_PARALLEL` (default: `true`): enable parallel function
  type-correlation.
- `FI_DEBUG_CORRELATE_WORKERS` (default: `min(cpu_count, 8)`): worker cap for
  type-correlation.
- `FI_DEBUG_CORRELATE_BACKEND` (default: `auto`): correlation backend for type-correlation.
  Supported: `auto`, `thread`, `process`.
- Correlator minimal recommended set:
  - `FI_DEBUG_CORRELATOR_BACKEND` (default: `python`)
  - `FI_DEBUG_CORRELATOR_BIN` (default: unset)
  - `FI_DEBUG_CORRELATOR_TIMEOUT_SEC` (default: unset)
  - `FI_DEBUG_CORRELATOR_STRICT` (default: `0`)
  - `FI_DEBUG_CORRELATOR_SHADOW` (default: `0`)
- `FI_DEBUG_CORRELATOR_BACKEND` (default: `python`): native correlator stage
  backend selector. Supported: `python`, `rust`, `go`.
- `FI_DEBUG_CORRELATOR_SHADOW` (default: `0`): run native correlator in
  shadow mode while Python output remains authoritative. Native still executes;
  mismatches versus Python are logged for investigation. With strict mode
  enabled, shadow mismatches fail the run.
- `FI_DEBUG_CORRELATOR_SHADOW_SAMPLE_SIZE` (default: `256`, optional advanced
  tuning): cap mismatch
  comparison/logging volume in shadow mode by sampling this many entries.
  Set `0` to opt in to full-output compare/logging.
- `FI_DEBUG_CORRELATOR_STRICT` (default: `0`): strict verification mode for
  native correlator stage. When set to `1`, native schema/version/timeout/exit
  failures and missing-row coverage fail the run (no Python fallback), even
  when shadow mode is enabled.
- `FI_DEBUG_CORRELATOR_TIMEOUT_SEC` (default: unset): timeout for native
  correlator command. On timeout, process-group termination + cleanup is
  enforced before optional fallback.
- Overlay backend minimal recommended set:
  - `FI_OVERLAY_BACKEND` (default: `python`): `python`, `native`, `rust`, `go`.
  - `FI_OVERLAY_BIN` (default: unset): command used for `FI_OVERLAY_BACKEND=native`.
  - `FI_OVERLAY_TIMEOUT_SEC` (default: unset): timeout for native overlay command.
  - `FI_OVERLAY_STRICT` (default: `0`): strict schema/version/status/timeout/exit handling.
  - `FI_OVERLAY_SHADOW` (default: `0`): run native+python and compare parity while
    keeping Python authoritative.
- Overlay backend advanced aliases (optional):
  - `FI_OVERLAY_RUST_BIN`: preferred command when `FI_OVERLAY_BACKEND=rust`.
  - `FI_OVERLAY_GO_BIN`: preferred command when `FI_OVERLAY_BACKEND=go`.
  - `FI_OVERLAY_BACKEND=rust|go` are compatibility aliases for the native backend
    family.
  - `FI_OVERLAY_BACKEND=go` is currently probe/shadow-only and never authoritative;
    Python overlay output remains authoritative even when `FI_OVERLAY_SHADOW=0`.
  - Native authoritative overlay application is currently gated to `target_lang=c-cpp`.
    Other languages use Python overlay output.
- Optional correlator advanced tuning (not required for normal operation):
- `FI_DEBUG_CORRELATOR_INPUT_SHARD_SIZE` (default: `250000`): records per input
  shard file written by Python before invoking native correlator.
- `FI_DEBUG_CORRELATOR_OUTPUT_SHARD_SIZE` (default: `5000`): records per output
  shard generated by native correlator.
- `FI_PROFILE_BACKEND` (default: `thread`): profile loading backend.
  Supported: `thread`, `process`.
- `FI_PROFILE_WORKERS` (default: `cpu_count`): worker cap for profile loading.
- `FI_CALLTREE_BITMAP_MAX_NODES` (default: `20000`): skip large calltree
  bitmap generation above this node count. `0` disables bitmap generation.
- `FI_STAGE_WARN_SECONDS` (default: `0`): emit warning when a report stage
  exceeds this duration in seconds. `0` disables warnings.
- `FI_DEBUG_YAML_LOADER` (default: `rust`): backend for debug YAML loader.
  Supported selectors: `python`, `go`, `rust`, `cpp`.
- `FI_PROFILE_YAML_LOADER` (default: `rust`): backend for profile YAML
  parsing. Supported selectors: `python`, `go`, `rust`, `cpp`.
- `FI_LLVM_COV_LOADER` (default: `rust`): backend for `.covreport` parsing.
  Supported selectors: `python`, `go`, `rust`, `cpp`.
- Backend binary configuration:
  - `FI_DEBUG_YAML_LOADER_<BACKEND>_BIN` or `FI_DEBUG_YAML_LOADER_BIN`
  - `FI_PROFILE_YAML_LOADER_<BACKEND>_BIN` or `FI_PROFILE_YAML_LOADER_BIN`
  - `FI_LLVM_COV_LOADER_<BACKEND>_BIN` or `FI_LLVM_COV_LOADER_BIN`
  - Prefer `FI_DEBUG_CORRELATOR_BIN`; `FI_DEBUG_CORRELATOR_RUST_BIN` and
    `FI_DEBUG_CORRELATOR_GO_BIN` are compatibility aliases.
  where `<BACKEND>` is uppercase (`GO`, `RUST`, `CPP`).
- Backend policy:
  - Rust is the default backend for all three loader surfaces.
  - Go remains available as an optional speed-focused backend mode.
  - Python remains the reliability fallback and is automatically used when a
    configured external backend is unavailable or fails.

Presets:

- Small/local (favor low overhead)
```bash
export FI_DEBUG_PARALLEL=true
export FI_DEBUG_MAX_WORKERS=2
export FI_DEBUG_SHARD_FILES=4
export FI_DEBUG_SPILL_MB=0
export FI_DEBUG_MAX_INMEM_MB=0
export FI_DEBUG_MAX_INFLIGHT_SHARDS=2
export FI_DEBUG_ADAPTIVE_WORKERS=0
export FI_DEBUG_SHARD_STRATEGY=fixed_count
export FI_DEBUG_RSS_SOFT_LIMIT_MB=0
export FI_DEBUG_CORRELATE_PARALLEL=true
export FI_DEBUG_CORRELATE_WORKERS=2
export FI_PROFILE_BACKEND=thread
export FI_CALLTREE_BITMAP_MAX_NODES=20000
export FI_STAGE_WARN_SECONDS=0
```

- Large host (favor throughput, >=16 CPU / >=96GB RAM)
```bash
export FI_DEBUG_PARALLEL=true
export FI_DEBUG_MAX_WORKERS=10
export FI_DEBUG_SHARD_FILES=4
export FI_DEBUG_SPILL_MB=4096
export FI_DEBUG_MAX_INMEM_MB=8192
export FI_DEBUG_MAX_INFLIGHT_SHARDS=6
export FI_DEBUG_ADAPTIVE_WORKERS=1
export FI_DEBUG_SHARD_STRATEGY=size_balanced
export FI_DEBUG_RSS_SOFT_LIMIT_MB=24576
export FI_DEBUG_CORRELATE_PARALLEL=true
export FI_DEBUG_CORRELATE_WORKERS=8
export FI_PROFILE_BACKEND=process
export FI_CALLTREE_BITMAP_MAX_NODES=40000
export FI_STAGE_WARN_SECONDS=180
```

- 24 CPU / 64GB RAM host (memory-balanced throughput)
```bash
export FI_DEBUG_PARALLEL=true
export FI_DEBUG_MAX_WORKERS=8
export FI_DEBUG_SHARD_FILES=4
export FI_DEBUG_SPILL_MB=3072
export FI_DEBUG_MAX_INMEM_MB=6144
export FI_DEBUG_MAX_INFLIGHT_SHARDS=8
export FI_DEBUG_ADAPTIVE_WORKERS=1
export FI_DEBUG_SHARD_STRATEGY=size_balanced
export FI_DEBUG_RSS_SOFT_LIMIT_MB=24576
export FI_DEBUG_CORRELATE_PARALLEL=true
export FI_DEBUG_CORRELATE_WORKERS=6
export FI_PROFILE_BACKEND=process
export FI_CALLTREE_BITMAP_MAX_NODES=30000
export FI_STAGE_WARN_SECONDS=180
```

- Low-memory CI (favor stability)
```bash
export FI_DEBUG_PARALLEL=true
export FI_DEBUG_MAX_WORKERS=2
export FI_DEBUG_SHARD_FILES=2
export FI_DEBUG_SPILL_MB=128
export FI_DEBUG_MAX_INMEM_MB=512
export FI_DEBUG_MAX_INFLIGHT_SHARDS=2
export FI_DEBUG_ADAPTIVE_WORKERS=0
export FI_DEBUG_SHARD_STRATEGY=size_balanced
export FI_DEBUG_RSS_SOFT_LIMIT_MB=1536
export FI_DEBUG_CORRELATE_PARALLEL=false
export FI_DEBUG_CORRELATE_WORKERS=1
export FI_PROFILE_BACKEND=thread
export FI_CALLTREE_BITMAP_MAX_NODES=5000
export FI_STAGE_WARN_SECONDS=120
```

Benchmark validation for these presets (dataset: `/home/nikita/work/Projects/cg/cgserver/build-introspector-full/introspector`, 49 `*.debug_all_*` files, Rust loader):
- low-memory CI:
  - wall time `228.81s`, CPU `41.50s`, max RSS `22819MB`.
- 24 CPU / 64GB RAM host:
  - wall time `188.06s`, CPU `37.08s`, max RSS `22824MB`.
- notes:
  - measured with default correlation backend settings (`auto`).

### Plugin/backend performance benchmarking

Run analysis-by-analysis benchmarks with backend matrix settings:

```bash
python3 benchmarks/run_plugin_backend_perf.py \
  --target-dir /path/to/introspector/artifacts \
  --language c-cpp \
  --disable-calltree-bitmap \
  --src-dir /path/to/project/src \
  --debug-yaml-loaders python \
  --profile-yaml-loaders python \
  --llvm-cov-loaders python go
```

This records elapsed time, CPU%, and max RSS (via `/usr/bin/time`) in
`benchmarks/results/plugin_backend_perf_results.json`.

Validate run outputs:

```bash
python3 benchmarks/validate_plugin_backend_perf.py \
  --results-json benchmarks/results/plugin_backend_perf_results.json
```

Compare backend output parity for LLVM coverage parser implementations:

```bash
python3 benchmarks/compare_llvm_cov_backends.py \
  --cov-dir /path/to/textcov_reports \
  --go-bin /tmp/native_llvm_cov_loader_go \
  --rust-bin /tmp/native_llvm_cov_loader_rust \
  --cpp-bin /tmp/native_llvm_cov_loader_cpp
```

CI policy for backend tests:

- CI and in-repo tests must use synthetic fixtures only.
- Real project datasets should be used for manual/offline benchmarking only.
- Do not commit large benchmark inputs or outputs.

## Architecture
The workflow of fuzz-introspector can be visualised as follows:
![Functions table](/doc/img/fuzz-introspector-architecture.png)

A more detailed description is available in [doc/Architecture](/doc/Architecture.md)

## Contribute
### Code of Conduct
Before contributing, please follow our [Code of Conduct](CODE_OF_CONDUCT.md).

### Preparing the PR for CI

You can run the `ci_checks.sh` script to run the linting and api tests that are
run during CI. Make sure to activate the Python virtual environment as it is
not done by the script to allow more flexibility for the local dev setup.
To lint the Python frontend directly, run
`flake8 --ignore E125,W503,W504,W605 --max-line-length 100 ./frontends/python/*.py`
from the repo root.

### Local Hook for Changed Files

To automatically run lint/format checks on changed Python files, enable the
`pre-commit` hook and use the included script:

```bash
git config core.hooksPath .githooks
./scripts/lint_changed_code.sh
```

The hook will run on staged and unstaged changed Python files and execute:

- `flake8 --ignore E125,W503,W504,W605 --max-line-length 100`
- `yapf -d`

Set `SKIP_CHANGED_HOOK=1` to bypass the hook for a single commit.

The commit message **needs** to contain a signoff line with your data, this is
supported by Git see [here](https://git-scm.com/docs/git-commit#Documentation/git-commit.txt---signoff).

### Connect with the Fuzzing Community
If you want to get involved in the Fuzzing community or have ideas to chat about, we discuss
this project in the
[OSSF Security Tooling Working Group](https://github.com/ossf/wg-security-tooling)
meetings.

More specifically, you can attend Fuzzing Collaboration meeting (monthly on
the first Tuesday 10:30am - 11:30am PST
[Calendar](https://calendar.google.com/calendar?cid=czYzdm9lZmhwNWk5cGZsdGI1cTY3bmdwZXNAZ3JvdXAuY2FsZW5kYXIuZ29vZ2xlLmNvbQ),
[Zoom
Link](https://zoom.us/j/99960722134?pwd=ZzZqdzY1eG9tMzQxWFI1Z0RhTkUxZz09)).
