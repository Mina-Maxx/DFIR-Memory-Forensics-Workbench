"""
Rule Engine Backward Compatibility Facade
Re-exports DetectionEngine and Indicator from backend.engines.detection
"""

from backend.engines.detection import DetectionEngine, Indicator, RuleEngine

__all__ = ["DetectionEngine", "Indicator", "RuleEngine"]
