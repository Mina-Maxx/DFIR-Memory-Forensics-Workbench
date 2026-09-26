"""
Core models facade preserving backward compatibility while pointing to backend.models.
"""
from backend.models import (
    Case, Evidence, Artifact, Detection, DetectionRule,
    Finding, FindingArtifact, FINDING_STATUSES,
    TimelineEvent, CustodyEvent, AnalystNote, Bookmark,
    IOC, DumpArtifact, RiskAssessment, IOC_STATUSES, IOC_TYPES,
    Process, DLL, MemoryRegion, NetworkConnection,
    PluginExecution, PluginResult
)

__all__ = [
    "Case", "Evidence", "Artifact", "Detection", "DetectionRule",
    "Finding", "FindingArtifact", "FINDING_STATUSES",
    "TimelineEvent", "CustodyEvent", "AnalystNote", "Bookmark",
    "IOC", "DumpArtifact", "RiskAssessment", "IOC_STATUSES", "IOC_TYPES",
    "Process", "DLL", "MemoryRegion", "NetworkConnection",
    "PluginExecution", "PluginResult"
]
