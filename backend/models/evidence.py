from dataclasses import dataclass, field, asdict
from typing import Optional
import uuid
from datetime import datetime

def get_uuid() -> str:
    return str(uuid.uuid4())

def get_timestamp() -> str:
    return datetime.now().isoformat()

@dataclass
class Evidence:
    filename: str
    filepath: str
    case_id: str
    file_size: int = 0
    sha256: str = ""
    md5: str = ""
    os_type: str = "Unknown"
    architecture: str = "Unknown"
    kernel_info: str = ""
    vol_compatibility: str = ""
    symbol_status: str = "Unknown"
    import_timestamp: str = field(default_factory=get_timestamp)
    acquisition_timestamp: str = ""
    status: str = "Ready"
    verification_status: str = "Verified"
    last_verified: str = field(default_factory=get_timestamp)
    metadata: str = "{}"
    id: str = field(default_factory=get_uuid)
    created_at: str = field(default_factory=get_timestamp)

    @classmethod
    def from_dict(cls, data: dict):
        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})

    def to_dict(self) -> dict:
        return asdict(self)
