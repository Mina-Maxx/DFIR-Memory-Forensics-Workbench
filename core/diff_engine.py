"""
Diff Engine Backward Compatibility Facade
Re-exports diff_evidence from backend.engines.diff
"""

from backend.engines.diff import diff_evidence

__all__ = ["diff_evidence"]
