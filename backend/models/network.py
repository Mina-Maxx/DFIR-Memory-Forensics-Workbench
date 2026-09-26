from dataclasses import dataclass, field, asdict
from typing import Optional
import uuid

def get_uuid() -> str:
    return str(uuid.uuid4())

@dataclass
class NetworkConnection:
    evidence_id: str
    pid: int = 0
    process_name: str = ""
    local_addr: str = ""
    local_port: int = 0
    remote_addr: str = ""
    remote_port: int = 0
    protocol: str = "TCP"
    state: str = ""
    created_time: str = ""
    owner: str = ""
    scope: str = "Internal"         # Internal, External, Loopback
    is_ioc: bool = False
    threat_intel: str = "Unknown"   # Unknown, Benign, Suspicious, Malicious
    id: str = field(default_factory=get_uuid)

    @classmethod
    def from_dict(cls, data: dict):
        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})

    def to_dict(self) -> dict:
        return asdict(self)
