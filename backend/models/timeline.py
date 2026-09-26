from dataclasses import dataclass, field, asdict
from typing import Optional
import uuid
from datetime import datetime

def get_uuid() -> str:
    return str(uuid.uuid4())

def get_timestamp() -> str:
    return datetime.now().isoformat()

@dataclass
class TimelineEvent:
    evidence_id: str
    timestamp: str
    event_type: str
    description: str
    case_id: str = ""
    pid: Optional[int] = None
    process_name: str = ""
    entity_id: str = ""
    source_plugin: str = ""
    plugin_execution_id: str = ""
    source_artifact_id: str = ""
    confidence: str = "High"        # High, Medium, Low
    severity: str = "Low"           # Critical, High, Medium, Low, Info
    inferred: bool = False          # False = directly observed; True = analytically deduced
    details: str = "{}"
    id: str = field(default_factory=get_uuid)
    created_at: str = field(default_factory=get_timestamp)

    @classmethod
    def from_dict(cls, data: dict):
        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})

    def to_dict(self) -> dict:
        return asdict(self)
