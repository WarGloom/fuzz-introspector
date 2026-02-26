"""
Analysis worker result envelope schema and validation utilities.
"""

import dataclasses
import logging
from typing import Any, Dict, List, Optional

from fuzz_introspector.exceptions import FuzzIntrospectorError

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class AnalysisWorkerResult:
    """Envelope schema for analysis worker results."""

    # Worker identifier (e.g., analysis name or ID)
    worker_id: str

    # Analysis result data (can be any serializable type)
    result: Any

    # Optional error information if analysis failed
    error: Optional[Dict[str, Any]] = None

    # Optional metadata about the analysis
    metadata: Optional[Dict[str, Any]] = None

    # Timestamp when the analysis completed
    timestamp: Optional[float] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AnalysisWorkerResult":
        """Create instance from dictionary with validation."""
        try:
            # Validate required fields
            if not isinstance(data.get("worker_id"), str):
                raise FuzzIntrospectorError("worker_id must be a string")

            if "result" not in data:
                raise FuzzIntrospectorError("result field is required")

            # Create instance
            return cls(
                worker_id=data["worker_id"],
                result=data["result"],
                error=data.get("error"),
                metadata=data.get("metadata"),
                timestamp=data.get("timestamp"),
            )
        except Exception as e:
            logger.error(f"Failed to validate AnalysisWorkerResult: {e}")
            raise FuzzIntrospectorError(
                f"Invalid analysis worker result: {e}") from e

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return dataclasses.asdict(self)


class AnalysisWorkerResultValidator:
    """Utility for validating analysis worker results."""

    @staticmethod
    def validate_result(data: Dict[str, Any]) -> AnalysisWorkerResult:
        """Validate and return AnalysisWorkerResult instance."""
        return AnalysisWorkerResult.from_dict(data)

    @staticmethod
    def validate_results_list(
        results: List[Dict[str, Any]], ) -> List[AnalysisWorkerResult]:
        """Validate list of results."""
        validated = []
        for idx, result in enumerate(results):
            try:
                validated.append(AnalysisWorkerResult.from_dict(result))
            except FuzzIntrospectorError as e:
                logger.warning(f"Skipping invalid result at index {idx}: {e}")
        return validated

    @staticmethod
    def is_valid_result(data: Dict[str, Any]) -> bool:
        """Check if data is a valid result without raising."""
        try:
            AnalysisWorkerResult.from_dict(data)
            return True
        except FuzzIntrospectorError:
            return False


def get_canonical_analysis_order(
        requested_analyses: List[str],
        analysis_registry: Dict[str, Any]) -> List[str]:
    """Resolve canonical order for requested analyses based on registry.

    Args:
        requested_analyses: List of analysis names requested by user
        analysis_registry: Dictionary mapping analysis names to analysis classes

    Returns:
        List of analysis names in canonical order
    """
    # Get all available analysis names from registry
    available_analyses = list(analysis_registry.keys())

    # Filter to only requested analyses that exist in registry
    valid_requested = [
        analysis for analysis in requested_analyses
        if analysis in available_analyses
    ]

    # Return in the order they appear in the registry (canonical order)
    # This ensures consistent ordering across runs
    return valid_requested


def validate_analysis_order(requested_analyses: List[str],
                            analysis_registry: Dict[str, Any]) -> None:
    """Validate that requested analyses are valid and can be ordered.

    Args:
        requested_analyses: List of analysis names requested by user
        analysis_registry: Dictionary mapping analysis names to analysis classes

    Raises:
        FuzzIntrospectorError: If any analysis is invalid or ordering fails
    """
    # Check if all requested analyses exist in registry
    for analysis in requested_analyses:
        if analysis not in analysis_registry:
            raise FuzzIntrospectorError(
                f"Analysis '{analysis}' is not registered. "
                f"Available analyses: {list(analysis_registry.keys())}")

    # Validate that we can get canonical order
    try:
        get_canonical_analysis_order(requested_analyses, analysis_registry)
    except Exception as e:
        raise FuzzIntrospectorError(
            f"Failed to resolve analysis order: {e}") from e
