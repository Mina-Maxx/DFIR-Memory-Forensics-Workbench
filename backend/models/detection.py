from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
import uuid
import json
from datetime import datetime

def get_uuid() -> str:
    return str(uuid.uuid4())

def get_timestamp() -> str:
    return datetime.now().isoformat()

@dataclass
class DetectionRule:
    id: str
    name: str
    description: str
    category: str
    weight: int = 10
    conditions: str = "[]"
    confidence: str = "Medium"   # Low, Medium, High
    severity: str = "Medium"     # Critical, High, Medium, Low, Info
    references_json: str = "[]"
    mitre_attack: str = "[]"     # e.g. [{"id": "T1055", "name": "Process Injection", "status": "Potential"}]
    mitre_tactic: str = ""
    mitre_technique_id: str = ""
    mitre_technique_name: str = ""
    enabled: bool = True
    version: str = "2.0"
    author: str = "DFIR Research"
    created_at: str = field(default_factory=get_timestamp)

    @property
    def rule_id(self) -> str:
        return self.id

    @classmethod
    def from_dict(cls, data: dict):
        d = dict(data)
        if "rule_id" in d and "id" not in d:
            d["id"] = d["rule_id"]
        return cls(**{k: v for k, v in d.items() if k in cls.__annotations__})

    def to_dict(self) -> dict:
        return asdict(self)


class Detection:
    def __init__(
        self,
        case_id: str = "",
        evidence_id: str = "",
        rule_id: str = "",
        name: str = "",
        category: str = "",
        entity_id: str = "",
        entity_type: str = "process",
        severity: str = "Medium",
        confidence: str = "Medium",
        reason: str = "",
        mitre_attack: str = "[]",
        mitre_tactic: str = "",
        mitre_technique_id: str = "",
        mitre_technique_name: str = "",
        supporting_artifacts: str = "[]",
        contributing_factors: str = "",
        id: Optional[str] = None,
        created_at: Optional[str] = None,
        **kwargs
    ):
        self.case_id = case_id
        self.evidence_id = evidence_id
        self.rule_id = rule_id or kwargs.get("id", "")
        self.name = name or kwargs.get("rule_name", "")
        self.category = category
        self.entity_id = entity_id or kwargs.get("affected_entity", "")
        self.entity_type = entity_type
        self.severity = severity
        self.confidence = confidence
        self.reason = reason or kwargs.get("explanation", "")
        self.mitre_attack = mitre_attack
        self.mitre_tactic = mitre_tactic
        self.mitre_technique_id = mitre_technique_id
        self.mitre_technique_name = mitre_technique_name
        self.supporting_artifacts = supporting_artifacts
        self.contributing_factors = contributing_factors
        self.id = id or get_uuid()
        self.created_at = created_at or get_timestamp()

    @property
    def rule_name(self) -> str:
        return self.name

    @property
    def explanation(self) -> str:
        return self.reason

    @property
    def affected_entity(self) -> str:
        return self.entity_id

    @classmethod
    def from_dict(cls, data: dict):
        return cls(**data)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "rule_id": self.rule_id,
            "name": self.name,
            "category": self.category,
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "reason": self.reason,
            "mitre_attack": self.mitre_attack,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique_id": self.mitre_technique_id,
            "mitre_technique_name": self.mitre_technique_name,
            "supporting_artifacts": self.supporting_artifacts,
            "contributing_factors": self.contributing_factors,
            "created_at": self.created_at
        }

    def get_supporting_artifacts(self) -> List[str]:
        try:
            return json.loads(self.supporting_artifacts)
        except Exception:
            return []
