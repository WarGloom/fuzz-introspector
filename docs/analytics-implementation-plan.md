# Coverage Analytics Dashboard — Implementation Plan

> Generated: 2026-03-03  
> Status: Active  
> Owner: orchestrator

---

## Overview

Build a unified `/analytics` page connecting introspector, coverage, attack surface, and fuzz scope data into a multi-layer coverage pyramid with drill-down, gap analysis, and regression detection.

This plan is agent-annotated: each task identifies which specialist agent owns it, and which tasks can run in parallel.

---

## Real Numbers (Current DB State)

| Metric | Value |
|--------|-------|
| Total codebase | 258,420 lines \| 17,624 functions |
| Combined runtime coverage | **8.18% lines \| 11.08% functions** (53 fuzzers, true llvm-cov union) |
| Attack surface components | 77 with IDs (483 total, 406 unmapped) |
| Fuzz scope targets | 83 (49 exist / 34 missing) |
| Per-fuzzer reachability efficiency | 33% – 91% (`cov-reach-proportion` from introspector) |
| Introspector reports | 9 |
| File coverage rows | 647K (58K with actual hits) |

---

## Coverage Pyramid (Conceptual Model)

```
Layer 0  Total Codebase         258,420 lines  │  17,624 functions
         ──────────────────────────────────────────────────────────
Layer 1  Attack Surface         77 components defined
         (of 483 total; 406 have no AS ID)
         ──────────────────────────────────────────────────────────
Layer 2  Fuzz Scope             83 targets (49 exist / 34 missing)
         ──────────────────────────────────────────────────────────
Layer 3  Statically Reachable   9 – 197 funcs/fuzzer (introspector)
         ──────────────────────────────────────────────────────────
Layer 4  Runtime Covered        8.18% lines │ 11.08% functions
```

Each layer can be drilled into for per-component / per-fuzzer details.

---

## Data Gaps to Fill

| Gap | Location | Fix | Phase |
|-----|----------|-----|-------|
| `file_coverage.component_path` always NULL | coverage sync | Match file paths to component rules during import | 2.1 |
| `components.coverage_percent` always 0 | sync post-step | Call `aggregateAttackSurfaceCoverage()` after sync | 2.2 |
| `fuzz_scopes.lines_min_percent` NULL | ingestion | Fall back to `fuzz_scope_defaults.lines_min_percent` | 2.2 |
| Introspector global `total-functions` | loader/API | Extract from `MergedProjectProfile.stats` in summary_json | 3.1 |
| Cross-fuzzer function union | analytics layer | Compute from per-fuzzer `Reached by Fuzzers` arrays | 3.1 |

---

## Phases

### Phase 1 — Per-Fuzzer Reachability Table  `[PRIORITY: HIGH — START IMMEDIATELY]`

**Goal:** New `/analytics` page showing per-fuzzer introspector-based reachability metrics.  
**Data:** `introspector_reports.summary_json → fuzzers.<name>.coverage-blocker-stats`  
**No new DB computation needed — data already exists.**

API contract (response shape for UX to build against):
```typescript
// GET /api/analytics/reachability
type ReachabilityResponse = {
  fuzzers: {
    name: string                 // display name (normalized)
    reachableFuncs: number       // from introspector: reachable-funcs
    reachedFuncs: number         // from introspector: reached-funcs
    covReachProportion: number   // cov-reach-proportion (0–100)
    totalBasicBlocks: number     // total-basic-blocks
    cyclomaticComplexity: number // total-cyclomatic-complexity
    coveragePercent: number      // from fuzzers table
    reachableFiles: number       // from fuzzers table
  }[]
  summary: {
    totalFuzzers: number
    avgCovReachProportion: number
    minCovReachProportion: number
    maxCovReachProportion: number
  }
  introspectorReportId: number | null
  reportedAt: string | null
}
```

| # | Task | **Agent** | Parallel With | Dependencies |
|---|------|-----------|---------------|--------------|
| 1.1 | `frontend/lib/analytics/reachability.ts` — query helper extracting per-fuzzer blocker stats from latest introspector report + join with fuzzers table | **dev** | 1.2, 1.3 | — |
| 1.2 | `frontend/app/api/analytics/reachability/route.ts` — GET handler, zod validation, response shaping | **dev** | 1.1, 1.3 | — |
| 1.3 | `frontend/lib/analytics/types.ts` — shared TypeScript types for all analytics APIs | **dev** | 1.1, 1.2 | — |
| 1.4 | `frontend/app/analytics/page.tsx` — page skeleton, nav link, layout | **ux** | — | 1.1–1.3 spec known |
| 1.5 | `frontend/components/analytics/reachability-table.tsx` — sortable table: fuzzer / reachable / reached / ratio / coverage% / complexity | **ux** | 1.4 | API contract above |
| 1.6 | Tests: `__tests__/api/analytics/reachability.test.ts` + `__tests__/components/analytics/reachability-table.test.tsx` | **test-engineer** | — | 1.1–1.5 |

**Parallelism:**
- `[1.1, 1.2, 1.3]` → can all start simultaneously (pure backend, no deps)
- `[1.4, 1.5]` → can run in parallel with 1.1–1.3 using the API contract above as spec
- `[1.6]` → after all above complete

---

### Phase 2 — Attack Surface Coverage Bridge  `[PRIORITY: HIGH]`

**Goal:** Populate the missing bridge between `file_coverage` and `components`, then surface AS coverage % on the analytics page.  
**Key existing code:** `aggregateAttackSurfaceCoverage()` in `frontend/lib/fuzz-scope/coverage.ts` — logic already written, just not called systematically.

| # | Task | **Agent** | Parallel With | Dependencies |
|---|------|-----------|---------------|--------------|
| 2.1 | Modify coverage sync to populate `file_coverage.component_path` by matching filenames against `components.files` JSON arrays during import | **dev** | 2.2 | Phase 1 complete |
| 2.2 | Post-sync step: call `aggregateAttackSurfaceCoverage()` → write results to `components.coverage_percent`, `components.covered_lines`, `components.total_lines` | **dev** | 2.1 | Phase 1 complete |
| 2.3 | `frontend/app/api/analytics/attack-surface/route.ts` — GET handler returning per-component coverage with risk, fuzzer mappings, gap flags | **dev** | 2.4 | 2.1, 2.2 |
| 2.4 | `frontend/components/analytics/attack-surface-coverage.tsx` — risk-heatmap table: AS ID / component / risk / coverage% / fuzz scopes mapped / coverage gap | **ux** | 2.3 | Phase 1 page exists |
| 2.5 | Tests for 2.1–2.4 | **test-engineer** | — | 2.1–2.4 |

**Parallelism:**
- `[2.1, 2.2]` → both touch coverage sync but separate concerns; can run in parallel carefully
- `[2.3, 2.4]` → can start in parallel once 2.1/2.2 produce data shape
- `[2.5]` → after all above

---

### Phase 3 — Full Pyramid View  `[PRIORITY: MEDIUM]`

**Goal:** Visual coverage pyramid with all 5 layers, drill-down, and gap summary sidebar.

**Depends on:** Phase 1 + Phase 2 complete.

| # | Task | **Agent** | Parallel With | Dependencies |
|---|------|-----------|---------------|--------------|
| 3.1 | `frontend/app/api/analytics/pyramid/route.ts` — aggregates all layers: codebase totals, AS stats, fuzz scope counts, introspector global, runtime coverage | **dev** | 3.2 | Phase 1+2 |
| 3.2 | `frontend/app/api/analytics/gaps/route.ts` — returns: missing harnesses (34), unmapped AS (406), uncovered top functions from introspector | **dev** | 3.1 | Phase 1+2 |
| 3.3 | `frontend/components/analytics/coverage-pyramid.tsx` — layered bar/funnel visualization, each layer clickable for drill-down | **ux** | 3.4 | 3.1 |
| 3.4 | `frontend/components/analytics/gap-summary.tsx` — sidebar: missing harnesses list, unmapped AS entries, top uncovered functions | **ux** | 3.3 | 3.2 |
| 3.5 | Tests | **test-engineer** | — | 3.1–3.4 |

**Parallelism:**
- `[3.1, 3.2]` → fully parallel (independent endpoints)
- `[3.3, 3.4]` → parallel after APIs exist

---

### Phase 4 — Regression Detection  `[PRIORITY: MEDIUM]`

**Goal:** Coverage trend tracking, introspector diff integration showing what degraded between runs.

**Depends on:** Phase 1 complete (reachability baseline).

| # | Task | **Agent** | Parallel With | Dependencies |
|---|------|-----------|---------------|--------------|
| 4.1 | `frontend/app/api/analytics/regression/route.ts` — snapshot trend diffs (coverage_percent delta between last N snapshots, trend_direction/velocity) | **dev** | 4.2 | Phase 1 |
| 4.2 | Wire introspector diff into regression: surface `coverage_changes.decreased[]` and `reachability_changes` from `introspector_diffs` table | **dev** | 4.1 | Phase 1 |
| 4.3 | `frontend/components/analytics/regression-timeline.tsx` — timeline: coverage % over time, degraded functions list, reachability lost/gained | **ux** | — | 4.1, 4.2 |
| 4.4 | Tests | **test-engineer** | — | 4.1–4.3 |

**Parallelism:**
- `[4.1, 4.2]` → fully parallel (different data sources)
- `[4.3]` → after 4.1 + 4.2

---

## Parallel Execution Rounds

```
Round 1  [Phase 1, all parallel]
  Thread A (dev)  →  1.1 query helper  +  1.2 API route  +  1.3 types
  Thread B (ux)   →  1.4 page skeleton +  1.5 ReachabilityTable (using API contract spec)

Round 2  [Phase 2, after Round 1]
  Thread A (dev)  →  2.1 component_path population
  Thread B (dev)  →  2.2 AS aggregation post-sync
  Thread C (ux)   →  2.4 AttackSurfaceCoverage component (from 2.3 spec)

Round 3  [Phase 3, after Round 2]
  Thread A (dev)  →  3.1 pyramid API  +  3.2 gaps API
  Thread B (ux)   →  3.3 CoveragePyramid  +  3.4 GapSummary

Round 4  [Phase 4, can start after Round 1]
  Thread A (dev)  →  4.1 regression API  +  4.2 introspector diff wire-in
  Thread B (ux)   →  4.3 RegressionTimeline

Round 5  [Tests — per-phase, after each round]
  test-engineer   →  Phase 1 tests → Phase 2 tests → Phase 3 tests → Phase 4 tests
```

---

## New Files Expected

### Backend
```
frontend/lib/analytics/types.ts
frontend/lib/analytics/reachability.ts
frontend/lib/analytics/attack-surface.ts
frontend/lib/analytics/pyramid.ts
frontend/lib/analytics/regression.ts
frontend/app/api/analytics/reachability/route.ts
frontend/app/api/analytics/attack-surface/route.ts
frontend/app/api/analytics/pyramid/route.ts
frontend/app/api/analytics/gaps/route.ts
frontend/app/api/analytics/regression/route.ts
```

### Frontend
```
frontend/app/analytics/page.tsx
frontend/app/analytics/layout.tsx         (if needed)
frontend/components/analytics/reachability-table.tsx
frontend/components/analytics/coverage-pyramid.tsx
frontend/components/analytics/attack-surface-coverage.tsx
frontend/components/analytics/gap-summary.tsx
frontend/components/analytics/regression-timeline.tsx
```

### Tests
```
frontend/__tests__/api/analytics/reachability.test.ts
frontend/__tests__/api/analytics/attack-surface.test.ts
frontend/__tests__/api/analytics/pyramid.test.ts
frontend/__tests__/api/analytics/gaps.test.ts
frontend/__tests__/api/analytics/regression.test.ts
frontend/__tests__/lib/analytics/reachability.test.ts
frontend/__tests__/components/analytics/reachability-table.test.tsx
frontend/__tests__/components/analytics/coverage-pyramid.test.tsx
frontend/__tests__/components/analytics/gap-summary.test.tsx
```

---

## Agent Responsibility Map

| Agent | Owns |
|-------|------|
| **dev** | All API routes, query helpers, DB bridge logic, sync modifications |
| **ux** | All React components, page layouts, visualizations |
| **test-engineer** | All tests across API routes, components, and library functions |
| **oracle** | Architecture decisions (called on-demand if design questions arise) |
| **code-reviewer** | Final review before each phase is merged |

---

## Acceptance Criteria per Phase

### Phase 1 ✅ Done when:
- [ ] `/analytics` page loads without error
- [ ] ReachabilityTable shows all 53 fuzzers with reachable/reached/ratio/complexity
- [ ] Data matches `introspector_reports` DB values
- [ ] Sortable by any column
- [ ] API returns correct shape, validated by zod
- [ ] Tests pass, lint clean

### Phase 2 ✅ Done when:
- [ ] `components.coverage_percent` populated after coverage sync
- [ ] Attack surface section on `/analytics` shows per-component coverage %
- [ ] Risk level and fuzzer mapping visible per component
- [ ] Gap flag visible for components with 0 or below-threshold coverage

### Phase 3 ✅ Done when:
- [ ] Pyramid visualization shows all 5 layers with correct numbers
- [ ] Gap summary shows 34 missing harnesses + unmapped AS entries
- [ ] Drill-down from pyramid layer works
- [ ] Top uncovered functions listed with complexity scores

### Phase 4 ✅ Done when:
- [ ] Coverage trend visible over last N snapshots
- [ ] Degraded functions highlighted (from introspector diff)
- [ ] Reachability lost/gained shown per report pair
- [ ] Alerts link to security_alerts table

---

_Last updated: 2026-03-03 by orchestrator_
