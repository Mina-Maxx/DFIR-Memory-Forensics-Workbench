from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
import uuid
from datetime import datetime

def get_uuid() -> str:
    return str(uuid.uuid4())

def get_timestamp() -> str:
    return datetime.now().isoformat()

@dataclass
class Process:
    evidence_id: str
    pid: int = 0
    ppid: int = 0
    name: str = ""
    path: str = ""
    command_line: str = ""
    create_time: str = ""
    exit_time: str = ""
    session_id: int = 0
    user_info: str = ""
    in_pslist: bool = False
    in_psscan: bool = False
    in_pstree: bool = False
    risk_score: int = 0
    risk_level: str = "Normal"      # Critical, High Risk, Suspicious, Normal
    confidence: str = "Medium"      # High, Medium, Low
    severity: str = "Normal"        # Critical, High, Medium, Low, Info
    verdict: str = "unreviewed"     # unreviewed, investigating, confirmed, false_positive, benign
    risk_details: str = "[]"
    metadata: str = "{}"
    id: str = field(default_factory=get_uuid)

    @classmethod
    def from_dict(cls, data: dict):
        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DLL:
    evidence_id: str
    pid: int
    name: str
    path: str
    base_address: str
    size: int
    id: str = field(default_factory=get_uuid)

    @classmethod
    def from_dict(cls, data: dict):
        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class MemoryRegion:
    evidence_id: str
    pid: int
    start_address: str
    protection: str
    tag: str = ""
    suspicious: bool = False
    details: str = ""
    id: str = field(default_factory=get_uuid)

    @classmethod
    def from_dict(cls, data: dict):
        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})

    def to_dict(self) -> dict:
        return asdict(self)
