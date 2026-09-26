from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, Union
import uuid
import json
import hashlib
from datetime import datetime

def get_uuid() -> str:
    return str(uuid.uuid4())

def get_timestamp() -> str:
    return datetime.now().isoformat()

@dataclass
class Artifact:
    case_id: str
    evidence_id: str
    artifact_type: str
    source_plugin: str
    entity_id: str
    source_execution_id: str = ""
    timestamp: str = ""
    raw_reference: str = ""
    normalized_data: Any = "{}"
    hash: str = ""
    id: str = field(default_factory=get_uuid)
    created_at: str = field(default_factory=get_timestamp)

    def __post_init__(self):
        if not self.hash and self.normalized_data:
            if isinstance(self.normalized_data, (dict, list)):
                self.hash = hashlib.sha256(json.dumps(self.normalized_data, sort_keys=True).encode("utf-8")).hexdigest()
            else:
                self.hash = hashlib.sha256(str(self.normalized_data).encode("utf-8")).hexdigest()

    @classmethod
    def from_dict(cls, data: dict):
        d = dict(data)
        if isinstance(d.get("normalized_data"), str):
            try:
                d["normalized_data"] = json.loads(d["normalized_data"])
            except Exception:
                pass
        return cls(**{k: v for k, v in d.items() if k in cls.__annotations__})

    def to_dict(self) -> dict:
        d = asdict(self)
        if isinstance(d.get("normalized_data"), (dict, list)):
            d["normalized_data"] = json.dumps(d["normalized_data"])
        return d

    def get_data(self) -> Dict[str, Any]:
        if isinstance(self.normalized_data, dict):
            return self.normalized_data
        try:
            return json.loads(self.normalized_data)
        except Exception:
            return {}
