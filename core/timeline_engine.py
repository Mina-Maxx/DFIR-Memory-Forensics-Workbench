"""
Timeline Engine Backward Compatibility Facade
Re-exports TimelineEngine from backend.engines.timeline
"""

from backend.engines.timeline import TimelineEngine

__all__ = ["TimelineEngine"]
