# Copyright 2025 Fuzz Introspector Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Initialisation of AnalysisInterface instances"""

from fuzz_introspector import analysis
from fuzz_introspector.analyses import bug_digestor
from fuzz_introspector.analyses import driver_synthesizer
from fuzz_introspector.analyses import engine_input
from fuzz_introspector.analyses import filepath_analyser
from fuzz_introspector.analyses import function_call_analyser
from fuzz_introspector.analyses import metadata
from fuzz_introspector.analyses import optimal_targets
from fuzz_introspector.analyses import runtime_coverage_analysis
from fuzz_introspector.analyses import sinks_analyser
from fuzz_introspector.analyses import annotated_cfg
from fuzz_introspector.analyses import source_code_line_analyser
from fuzz_introspector.analyses import far_reach_low_coverage_analyser
from fuzz_introspector.analyses import public_candidate_analyser
from fuzz_introspector.analyses import frontend_analyser

PARALLEL_COMPATIBILITY_PARALLEL_SAFE = "parallel_safe"
PARALLEL_COMPATIBILITY_SERIAL_ONLY = "serial_only"

# All optional analyses.
# Ordering here is important as top analysis will be shown first in the report
all_analyses: list[type[analysis.AnalysisInterface]] = [
    optimal_targets.OptimalTargets,
    engine_input.EngineInput,
    runtime_coverage_analysis.RuntimeCoverageAnalysis,
    driver_synthesizer.DriverSynthesizer,
    bug_digestor.BugDigestor,
    filepath_analyser.FilePathAnalysis,
    function_call_analyser.ThirdPartyAPICoverageAnalyser,
    metadata.MetadataAnalysis,
    sinks_analyser.SinkCoverageAnalyser,
    annotated_cfg.FuzzAnnotatedCFG,
    source_code_line_analyser.SourceCodeLineAnalyser,
    far_reach_low_coverage_analyser.FarReachLowCoverageAnalyser,
    public_candidate_analyser.PublicCandidateAnalyser,
    frontend_analyser.FrontendAnalyser,
]

# Explicit PR6 analysis compatibility matrix.
analysis_parallel_compatibility = {
    optimal_targets.OptimalTargets: PARALLEL_COMPATIBILITY_SERIAL_ONLY,
    engine_input.EngineInput: PARALLEL_COMPATIBILITY_SERIAL_ONLY,
    runtime_coverage_analysis.RuntimeCoverageAnalysis:
    PARALLEL_COMPATIBILITY_PARALLEL_SAFE,
    driver_synthesizer.DriverSynthesizer: PARALLEL_COMPATIBILITY_PARALLEL_SAFE,
    bug_digestor.BugDigestor: PARALLEL_COMPATIBILITY_PARALLEL_SAFE,
    filepath_analyser.FilePathAnalysis: PARALLEL_COMPATIBILITY_PARALLEL_SAFE,
    function_call_analyser.ThirdPartyAPICoverageAnalyser:
    PARALLEL_COMPATIBILITY_PARALLEL_SAFE,
    metadata.MetadataAnalysis: PARALLEL_COMPATIBILITY_PARALLEL_SAFE,
    sinks_analyser.SinkCoverageAnalyser: PARALLEL_COMPATIBILITY_SERIAL_ONLY,
    annotated_cfg.FuzzAnnotatedCFG: PARALLEL_COMPATIBILITY_PARALLEL_SAFE,
    source_code_line_analyser.SourceCodeLineAnalyser:
    PARALLEL_COMPATIBILITY_SERIAL_ONLY,
    far_reach_low_coverage_analyser.FarReachLowCoverageAnalyser:
    PARALLEL_COMPATIBILITY_SERIAL_ONLY,
    public_candidate_analyser.PublicCandidateAnalyser:
    PARALLEL_COMPATIBILITY_SERIAL_ONLY,
    frontend_analyser.FrontendAnalyser: PARALLEL_COMPATIBILITY_SERIAL_ONLY,
}  # type: dict[type[analysis.AnalysisInterface], str]

# Analyses vetted for PR6 parallel worker execution.
parallel_safe_analyses: list[type[analysis.AnalysisInterface]] = [
    analysis_cls
    for analysis_cls, compatibility in analysis_parallel_compatibility.items()
    if compatibility == PARALLEL_COMPATIBILITY_PARALLEL_SAFE
]

# This is the list of analyses that are meant to run
# directly from CLI without the need to generate HTML reports
standalone_analyses: list[type[analysis.AnalysisInterface]] = [
    source_code_line_analyser.SourceCodeLineAnalyser,
    far_reach_low_coverage_analyser.FarReachLowCoverageAnalyser,
    public_candidate_analyser.PublicCandidateAnalyser,
    frontend_analyser.FrontendAnalyser,
]
