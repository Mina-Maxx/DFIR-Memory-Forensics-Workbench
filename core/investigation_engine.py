"""
Investigation Engine Backward Compatibility Facade
Re-exports CorrelatedProcess and InvestigationEngine from backend.engines.correlation
"""

from backend.engines.correlation.investigation_engine import CorrelatedProcess, InvestigationEngine

__all__ = ["CorrelatedProcess", "InvestigationEngine"]
