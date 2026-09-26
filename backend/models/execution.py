from dataclasses import dataclass, field, asdict
from typing import Optional
import uuid
from datetime import datetime

def get_uuid() -> str:
    return str(uuid.uuid4())

def get_timestamp() -> str:
    return datetime.now().isoformat()

@dataclass
class PluginExecution:
    evidence_id: str
    plugin_name: str
    arguments: str
    case_id: str = ""
    command: str = ""
    status: str = "Running"         # Queued, Running, Completed, Failed, Cancelled, Timed_Out
    current_activity: str = ""
    stdout_tail: str = ""
    stderr: str = ""
    error_message: str = ""
    raw_output_path: str = ""
    stdout_hash: str = ""
    stderr_hash: str = ""
    result_hash: str = ""
    vol_version: str = "3.x"
    volatility_version: str = "3.x"
    python_version: str = ""
    platform: str = ""
    plugin_version: str = ""
    symbol_table: str = ""
    configuration: str = "{}"
    working_directory: str = ""
    execution_host: str = "127.0.0.1"
    start_time: str = field(default_factory=get_timestamp)
    end_time: str = ""
    runtime_seconds: float = 0.0
    result_count: int = 0
    id: str = field(default_factory=get_uuid)
    created_at: str = field(default_factory=get_timestamp)

    def __post_init__(self):
        if self.vol_version and self.vol_version != "3.x" and self.volatility_version == "3.x":
            self.volatility_version = self.vol_version
        elif self.volatility_version and self.volatility_version != "3.x" and self.vol_version == "3.x":
            self.vol_version = self.volatility_version

    @classmethod
    def from_dict(cls, data: dict):
        d = dict(data)
        if "vol_version" in d and "volatility_version" not in d:
            d["volatility_version"] = d["vol_version"]
        elif "volatility_version" in d and "vol_version" not in d:
            d["vol_version"] = d["volatility_version"]
        return cls(**{k: v for k, v in d.items() if k in cls.__annotations__})

    def to_dict(self) -> dict:
        d = asdict(self)
        if "vol_version" not in d:
            d["vol_version"] = getattr(self, "volatility_version", "3.x")
        if "volatility_version" not in d:
            d["volatility_version"] = getattr(self, "vol_version", "3.x")
        return d


@dataclass
class PluginResult:
    execution_id: str
    evidence_id: str
    plugin_name: str
    headers: str
    data: str
    storage_mode: str = "inline"    # inline, file
    file_path: str = ""
    row_count: int = 0
    id: str = field(default_factory=get_uuid)
    created_at: str = field(default_factory=get_timestamp)

    @classmethod
    def from_dict(cls, data: dict):
        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})

    def to_dict(self) -> dict:
        return asdict(self)
