from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
import uuid
import json
from datetime import datetime

def get_uuid() -> str:
    return str(uuid.uuid4())

def get_timestamp() -> str:
    return datetime.now().isoformat()

FINDING_STATUSES = [
    "detected",
    "triaged",
    "investigating",
    "confirmed",
    "false_positive",
    "inconclusive",
    "closed"
]

@dataclass
class Finding:
    case_id: str
    title: str
    severity: str = "Medium"        # Critical, High, Medium, Low, Info
    confidence: str = "Medium"      # High, Medium, Low
    status: str = "detected"        # detected, triaged, investigating, confirmed, false_positive, inconclusive, closed
    source_type: str = "correlation"# automated_rule, manual_investigation, correlation, playbook
    affected_entity: str = ""       # e.g. "PID 4420 (powershell.exe)"
    associated_pid: int = 0
    associated_process_name: str = ""
    description: str = ""
    summary: str = ""
    technical_description: str = ""
    supporting_evidence: str = "[]" # JSON list of artifact IDs or description
    analyst_assessment: str = ""
    limitations: str = ""
    mitre_attack: str = "[]"
    threat_intel: str = ""
    investigator: str = ""
    id: str = field(default_factory=get_uuid)
    created_at: str = field(default_factory=get_timestamp)
    updated_at: str = field(default_factory=get_timestamp)

    # Aliases for backward compatibility
    @property
    def related_process(self) -> str:
        return self.associated_process_name or (self.affected_entity if "(" in self.affected_entity else "")

    @property
    def related_pid(self) -> int:
        return self.associated_pid

    @property
    def related_iocs(self) -> str:
        return ""

    @property
    def source_plugins(self) -> str:
        return self.source_type

    @property
    def evidence_details(self) -> str:
        return self.supporting_evidence

    @classmethod
    def from_dict(cls, data: dict):
        # Map legacy keys if present
        d = dict(data)
        if "related_pid" in d and "associated_pid" not in d:
            d["associated_pid"] = d["related_pid"]
        if "related_process" in d and "associated_process_name" not in d:
            d["associated_process_name"] = d["related_process"]
        return cls(**{k: v for k, v in d.items() if k in cls.__annotations__})

    def to_dict(self) -> dict:
        return asdict(self)

    def is_valid_status_transition(self, new_status: str) -> bool:
        return new_status in FINDING_STATUSES


@dataclass
class FindingArtifact:
    finding_id: str
    artifact_id: str
    case_id: str = ""
    role: str = "supports"          # supports, corroborates, observes, refutes
    explanation: str = ""
    relationship: str = "supports"  # alias for role
    id: str = field(default_factory=get_uuid)
    added_at: str = field(default_factory=get_timestamp)
    created_at: str = field(default_factory=get_timestamp)

    @classmethod
    def from_dict(cls, data: dict):
        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})

    def to_dict(self) -> dict:
        return asdict(self)
