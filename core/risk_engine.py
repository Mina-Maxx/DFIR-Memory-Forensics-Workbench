"""
Risk Engine Backward Compatibility Facade
Re-exports RiskEngine and thresholds from backend.engines.risk
"""

from backend.engines.risk import (
    RiskEngine,
    RISK_THRESHOLD_CRITICAL,
    RISK_THRESHOLD_HIGH,
    RISK_THRESHOLD_SUSPICIOUS
)

__all__ = [
    "RiskEngine",
    "RISK_THRESHOLD_CRITICAL",
    "RISK_THRESHOLD_HIGH",
    "RISK_THRESHOLD_SUSPICIOUS"
]
