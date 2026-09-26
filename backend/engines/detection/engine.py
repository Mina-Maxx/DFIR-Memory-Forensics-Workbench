"""
Detection Engine for DFIR Workbench V2
Handles heuristic detection rules, MITRE ATT&CK mapping, and detection event generation.
"""

from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import os
import threading
import json
import uuid
from datetime import datetime

from backend.models.detection import Detection, DetectionRule
from core.logger import get_logger

logger = get_logger("app")


@dataclass
class Indicator:
    rule_id: str
    rule_name: str
    category: str
    weight: int
    reason: str
    evidence_text: str
    confidence: str = "Medium"
    mitre_technique_id: str = ""
    mitre_technique_name: str = ""
    mitre_tactic: str = ""


class DetectionEngine:
    """Configurable collection of DFIR detection rules with thread-safe overrides,

    MITRE ATT&CK mappings, and detection generation.
    """

    EXPECTED_PARENTS = {
        "svchost.exe": ["services.exe"],
        "lsass.exe": ["wininit.exe"],
        "services.exe": ["wininit.exe"],
        "csrss.exe": ["smss.exe"],
        "winlogon.exe": ["smss.exe"],
        "spoolsv.exe": ["services.exe"],
        "lsm.exe": ["wininit.exe"]
    }

    EXPECTED_SYSTEM_PATHS = {
        "svchost.exe": r"c:\windows\system32\svchost.exe",
        "lsass.exe": r"c:\windows\system32\lsass.exe",
        "services.exe": r"c:\windows\system32\services.exe",
        "csrss.exe": r"c:\windows\system32\csrss.exe",
        "smss.exe": r"c:\windows\system32\smss.exe",
        "wininit.exe": r"c:\windows\system32\wininit.exe",
        "explorer.exe": r"c:\windows\explorer.exe"
    }

    TYPOSQUAT_TARGETS = [
        "svchost.exe", "scvhost.exe", "svch0st.exe", "svhost.exe", "svchosts.exe",
        "csrss.exe", "csrs.exe", "crss.exe",
        "lsass.exe", "lsas.exe", "lsasss.exe", "isass.exe",
        "smss.exe", "sms.exe",
        "winlogon.exe", "winlog0n.exe", "winlogin.exe",
        "services.exe", "servics.exe",
        "taskhost.exe", "taskhostw.exe",
        "taskmgr.exe", "taskmgrr.exe", "explorer.exe", "explorerr.exe"
    ]

    SINGLETON_PROCESSES = ["lsass.exe", "services.exe", "wininit.exe", "smss.exe", "lsm.exe"]

    def __init__(self, data_dir: Optional[str] = None):
        self._lock = threading.Lock()
        base_dir = data_dir or os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data")
        self.OVERRIDES_FILE = os.path.join(base_dir, "rule_overrides.json")
        self.rules: Dict[str, DetectionRule] = self._load_default_rules()
        self._apply_overrides()

    def _load_default_rules(self) -> Dict[str, DetectionRule]:
        rules_list = [
            DetectionRule(
                id="R-PARENT-01",
                name="Office Spawning Shell",
                description="Office process spawned PowerShell or CMD interpreter",
                category="Parent-Child",
                severity="High",
                confidence="High",
                mitre_tactic="Execution",
                mitre_technique_id="T1204.002",
                mitre_technique_name="User Execution: Malicious File",
                weight=30
            ),
            DetectionRule(
                id="R-PARENT-02",
                name="Browser Spawning Shell",
                description="Web browser spawned shell interpreter",
                category="Parent-Child",
                severity="High",
                confidence="High",
                mitre_tactic="Execution",
                mitre_technique_id="T1203",
                mitre_technique_name="Exploitation for Client Execution",
                weight=25
            ),
            DetectionRule(
                id="R-PARENT-03",
                name="Abnormal System Parent",
                description="Core Windows binary spawned by unexpected parent",
                category="Parent-Child",
                severity="High",
                confidence="Medium",
                mitre_tactic="Defense Evasion",
                mitre_technique_id="T1036.004",
                mitre_technique_name="Masquerading: Masquerade Task or Service",
                weight=25
            ),
            DetectionRule(
                id="R-PATH-01",
                name="System Binary in User Directory",
                description="Core Windows system binary executed from non-System32 path",
                category="Path",
                severity="High",
                confidence="High",
                mitre_tactic="Defense Evasion",
                mitre_technique_id="T1036.005",
                mitre_technique_name="Masquerading: Match Legitimate Name or Location",
                weight=25
            ),
            DetectionRule(
                id="R-PATH-02",
                name="Execution from Temp/AppData",
                description="Process executed from Temp, AppData, or Recycled folders",
                category="Path",
                severity="Medium",
                confidence="Medium",
                mitre_tactic="Defense Evasion",
                mitre_technique_id="T1036",
                mitre_technique_name="Masquerading",
                weight=15
            ),
            DetectionRule(
                id="R-MASQ-01",
                name="Process Name Masquerading",
                description="Process name resembles legitimate system service via typosquatting",
                category="Masquerading",
                severity="High",
                confidence="Medium",
                mitre_tactic="Defense Evasion",
                mitre_technique_id="T1036.003",
                mitre_technique_name="Masquerading: Rename System Utilities",
                weight=30
            ),
            DetectionRule(
                id="R-HIDDEN-01",
                name="Unlinked Process (DKOM)",
                description="Process found in psscan pool tags but unlinked from pslist (DKOM rootkit activity)",
                category="Hidden",
                severity="Critical",
                confidence="High",
                mitre_tactic="Defense Evasion",
                mitre_technique_id="T1014",
                mitre_technique_name="Rootkit",
                weight=40
            ),
            DetectionRule(
                id="R-MULTI-01",
                name="Multiple Singleton Instances",
                description="More than one instance of singleton system binary active",
                category="Multi-Instance",
                severity="High",
                confidence="Medium",
                mitre_tactic="Defense Evasion",
                mitre_technique_id="T1036",
                mitre_technique_name="Masquerading",
                weight=25
            ),
            DetectionRule(
                id="R-CMD-01",
                name="Encoded PowerShell Command",
                description="PowerShell execution with base64 encoded command arguments",
                category="CmdLine",
                severity="High",
                confidence="High",
                mitre_tactic="Execution",
                mitre_technique_id="T1059.001",
                mitre_technique_name="Command and Scripting Interpreter: PowerShell",
                weight=25
            ),
            DetectionRule(
                id="R-CMD-02",
                name="Suspicious CLI Tool Mention",
                description="Command line references credential dumping or reconnaissance tools",
                category="CmdLine",
                severity="High",
                confidence="Medium",
                mitre_tactic="Credential Access",
                mitre_technique_id="T1003",
                mitre_technique_name="OS Credential Dumping",
                weight=25
            ),
            DetectionRule(
                id="R-NET-01",
                name="Process with External Connections",
                description="Process established sockets to public non-RFC1918 IPs",
                category="Network",
                severity="Medium",
                confidence="Medium",
                mitre_tactic="Command and Control",
                mitre_technique_id="T1071",
                mitre_technique_name="Application Layer Protocol",
                weight=15
            ),
            DetectionRule(
                id="R-MEM-01",
                name="Injected Executable Memory (RWX)",
                description="VAD memory allocation with PAGE_EXECUTE_READWRITE permissions (Malfind)",
                category="Memory",
                severity="Critical",
                confidence="High",
                mitre_tactic="Defense Evasion",
                mitre_technique_id="T1055",
                mitre_technique_name="Process Injection",
                weight=35
            )
        ]
        return {r.id: r for r in rules_list}

    def _apply_overrides(self):
        with self._lock:
            try:
                if os.path.isfile(self.OVERRIDES_FILE):
                    with open(self.OVERRIDES_FILE, encoding="utf-8") as fh:
                        data = json.load(fh) or {}
                    for rid, ov in data.items():
                        r = self.rules.get(rid)
                        if not r:
                            continue
                        if "enabled" in ov:
                            r.enabled = bool(ov["enabled"])
                        if "weight" in ov:
                            r.weight = max(0, min(100, int(ov["weight"])))
            except Exception as exc:
                logger.error(f"Failed to apply rule overrides: {exc}")

    def list_rules(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [r.to_dict() for r in self.rules.values()]

    def set_override(self, rule_id: str, enabled: Optional[bool] = None, weight: Optional[int] = None) -> bool:
        with self._lock:
            r = self.rules.get(rule_id)
            if not r:
                return False
            if enabled is not None:
                r.enabled = bool(enabled)
            if weight is not None:
                r.weight = max(0, min(100, int(weight)))
            data = {}
            try:
                if os.path.isfile(self.OVERRIDES_FILE):
                    with open(self.OVERRIDES_FILE, encoding="utf-8") as fh:
                        data = json.load(fh) or {}
            except (ValueError, OSError):
                data = {}
            ov = data.setdefault(rule_id, {})
            if enabled is not None:
                ov["enabled"] = r.enabled
            if weight is not None:
                ov["weight"] = r.weight
            os.makedirs(os.path.dirname(self.OVERRIDES_FILE), exist_ok=True)
            with open(self.OVERRIDES_FILE, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
            logger.info(f"Rule override saved: {rule_id} enabled={r.enabled} weight={r.weight}")
            return True


# Backward compatibility alias
RuleEngine = DetectionEngine
