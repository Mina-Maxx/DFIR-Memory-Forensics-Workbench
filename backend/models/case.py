from dataclasses import dataclass, field, asdict
from typing import Optional
import uuid
from datetime import datetime

def get_uuid() -> str:
    return str(uuid.uuid4())

def get_timestamp() -> str:
    return datetime.now().isoformat()

@dataclass
class Case:
    id: str
    name: str
    investigator: str
    description: str
    created_at: str = field(default_factory=get_timestamp)
    updated_at: str = field(default_factory=get_timestamp)
    status: str = "Open"
    workspace_path: str = ""
    chain_of_custody: str = ""

    @classmethod
    def from_dict(cls, data: dict):
        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})

    def to_dict(self) -> dict:
        return asdict(self)
