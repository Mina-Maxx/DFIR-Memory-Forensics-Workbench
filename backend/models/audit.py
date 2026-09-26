from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
import uuid
from datetime import datetime

def get_uuid() -> str:
    return str(uuid.uuid4())

def get_timestamp() -> str:
    return datetime.now().isoformat()

IOC_STATUSES = ["Observed", "Suspicious", "Confirmed", "Benign", "Unknown"]
IOC_TYPES = [
    "IPv4", "IPv6", "Domain", "URL", "SHA256", "MD5", "SHA1",
    "Email", "File Path", "Mutex", "Registry Key", "Process Name", "Command Line"
]

@dataclass
class CustodyEvent:
    case_id: str
    action: str                     # e.g. "Evidence Imported", "Hash Calculated", "Analysis Started"
    evidence_id: Optional[str] = None
    actor: str = "Lead Investigator"
    source: str = ""
    destination: str = ""
    hash_before: str = ""
    hash_after: str = ""
    notes: str = ""
    metadata: str = "{}"
    timestamp: str = field(default_factory=get_timestamp)
    id: str = field(default_factory=get_uuid)

    # Aliases
    @property
    def details(self) -> str:
        return self.notes

    @property
    def sha256(self) -> str:
        return self.hash_after

    @property
    def verified(self) -> bool:
        return True

    @classmethod
    def from_dict(cls, data: dict):
        d = dict(data)
        if "details" in d and "notes" not in d:
            d["notes"] = d["details"]
        if "sha256" in d and "hash_after" not in d:
            d["hash_after"] = d["sha256"]
        return cls(**{k: v for k, v in d.items() if k in cls.__annotations__})

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AnalystNote:
    case_id: str
    entity_id: str = ""
    entity_type: str = "general"    # process, artifact, finding, ioc, general
    text: str = ""
    author: str = "Analyst"
    timestamp: str = field(default_factory=get_timestamp)
    created_at: str = field(default_factory=get_timestamp)
    id: str = field(default_factory=get_uuid)

    # Aliases
    @property
    def note(self) -> str:
        return self.text

    @classmethod
    def from_dict(cls, data: dict):
        d = dict(data)
        if "note" in d and "text" not in d:
            d["text"] = d["note"]
        return cls(**{k: v for k, v in d.items() if k in cls.__annotations__})

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Bookmark:
    case_id: str
    item_type: str                  # process, connection, dll, finding, artifact
    item_id: str
    notes: str = ""
    created_at: str = field(default_factory=get_timestamp)
    id: str = field(default_factory=get_uuid)

    @classmethod
    def from_dict(cls, data: dict):
        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class IOC:
    case_id: str
    type: str                       # IPv4, Domain, SHA256, etc.
    value: str
    severity: str = "Medium"        # Critical, High, Medium, Low, Info
    confidence: str = "Medium"      # High, Medium, Low
    status: str = "Observed"        # Observed, Suspicious, Confirmed, Benign, Unknown
    source: str = "Investigation"
    description: str = ""
    associated_finding_id: Optional[str] = None
    associated_pid: int = 0
    first_seen: str = ""
    last_seen: str = ""
    id: str = field(default_factory=get_uuid)
    created_at: str = field(default_factory=get_timestamp)

    @classmethod
    def from_dict(cls, data: dict):
        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DumpArtifact:
    case_id: str
    evidence_id: str
    dump_type: str
    source_plugin: str
    output_path: str
    sha256: str = ""
    pid: int = 0
    address: str = ""
    id: str = field(default_factory=get_uuid)
    created_at: str = field(default_factory=get_timestamp)

    @classmethod
    def from_dict(cls, data: dict):
        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RiskAssessment:
    evidence_id: str
    pid: int
    rule_id: str
    rule_name: str
    category: str
    weight: int
    reason: str
    evidence_text: str = ""
    confidence: str = "Medium"
    id: str = field(default_factory=get_uuid)
    created_at: str = field(default_factory=get_timestamp)

    @classmethod
    def from_dict(cls, data: dict):
        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})

    def to_dict(self) -> dict:
        return asdict(self)


# Backward compatibility alias
Note = AnalystNote
