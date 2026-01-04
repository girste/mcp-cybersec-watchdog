"""Base analyzer interface and utilities."""

from typing import Protocol, Dict, Any, List, Optional
from dataclasses import dataclass


class AnalyzerProtocol(Protocol):
    """
    Protocol defining the contract for all security analyzers.

    All analyzer functions should follow this signature to ensure
    consistency and enable auto-discovery.
    """

    def __call__(self, **kwargs) -> Optional[Dict[str, Any]]:
        """
        Run the security analysis.

        Returns:
            Dict with analysis results, or None if analyzer cannot run.
            Expected keys:
            - installed: bool (if applicable)
            - active: bool (if applicable)
            - issues: List[Dict] (optional)
            - Any analyzer-specific data
        """
        ...


@dataclass
class AnalyzerMetadata:
    """Metadata for analyzer registration."""

    name: str
    func: AnalyzerProtocol
    enabled_by_default: bool = True
    requires_sudo: bool = False
    kwargs: Dict[str, Any] = None

    def __post_init__(self):
        if self.kwargs is None:
            self.kwargs = {}


class AnalyzerResult:
    """
    Standardized analyzer result wrapper.

    Provides consistent interface for all analyzer outputs.
    """

    def __init__(self, data: Optional[Dict[str, Any]]):
        self._data = data or {}

    @property
    def is_available(self) -> bool:
        """Check if analyzer could run (e.g., tool installed)."""
        return self._data is not None and self._data.get("installed", True)

    @property
    def is_active(self) -> bool:
        """Check if analyzed feature is active."""
        return self._data.get("active", False)

    @property
    def issues(self) -> List[Dict[str, str]]:
        """Get list of issues found."""
        return self._data.get("issues", [])

    @property
    def raw_data(self) -> Dict[str, Any]:
        """Get raw analyzer data."""
        return self._data

    def get(self, key: str, default=None):
        """Get value from analyzer data."""
        return self._data.get(key, default)

    def __bool__(self) -> bool:
        """Analyzer result is truthy if available."""
        return self.is_available


def create_analyzer_result(
    installed: bool = True,
    active: bool = False,
    issues: Optional[List[Dict[str, str]]] = None,
    **extra_data,
) -> Dict[str, Any]:
    """
    Helper to create standardized analyzer result dict.

    Usage:
        return create_analyzer_result(
            installed=True,
            active=True,
            issues=[{"severity": "high", "message": "..."}],
            custom_field="value"
        )
    """
    result = {"installed": installed, "active": active}

    if issues is not None:
        result["issues"] = issues
    else:
        result["issues"] = []

    result.update(extra_data)
    return result
