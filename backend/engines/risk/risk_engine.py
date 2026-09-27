"""
DFIR Workbench V2 - Explainable Risk & Heuristic Scoring Engine
Separates Risk Score (0-100), Confidence, Severity, and Analyst Verdict.
Enforces strict forensic thresholds: Critical (>=70), High (>=40), Suspicious (>=20), Normal (<20).
"""

import os
import re
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional

from backend.engines.detection.engine import DetectionEngine, Indicator
from backend.models.detection import Detection
from core.logger import get_logger

logger = get_logger("forensic")

# Exact DFIR thresholds
RISK_THRESHOLD_CRITICAL = 70
RISK_THRESHOLD_HIGH = 40
RISK_THRESHOLD_SUSPICIOUS = 20


class RiskEngine:
    """Evaluates DFIR heuristic risk indicators for correlated processes, assigns 0-100 scores,

    and produces explainable detection breakdowns with MITRE ATT&CK mapping.
    """

    def __init__(self, rule_engine: Optional[DetectionEngine] = None):
        self.rules = rule_engine or DetectionEngine()

    def evaluate_process(
        self,
        process: Dict[str, Any],
        all_processes: List[Dict[str, Any]],
        network_connections: List[Dict[str, Any]],
        memory_anomalies: List[Dict[str, Any]],
        case_id: str = "",
        evidence_id: str = ""
    ) -> Dict[str, Any]:
        """Evaluates a process and returns risk score, level, confidence, severity,

        indicators, explainable summary, and generated Detection objects.
        """
        indicators: List[Indicator] = []
        name = (process.get("name") or "").lower()
        cmd = (process.get("command_line") or "").lower()
        path = (process.get("path") or "").lower()
        pid = process.get("pid", 0)
        ppid = process.get("ppid", 0)

        pid_map = {p.get("pid"): p for p in all_processes if p.get("pid") is not None}
        parent = pid_map.get(ppid)
        parent_name = (parent.get("name") or "").lower() if parent else ""

        # 1. Parent-child anomalies
        if parent_name in ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe") and name in ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"):
            r = self.rules.rules.get("R-PARENT-01")
            if r and r.enabled:
                indicators.append(Indicator(
                    r.id, r.name, r.category, r.weight,
                    f"Office process '{parent_name}' spawned shell '{name}'",
                    f"PID {pid} parent PID {ppid} ({parent_name})", "High",
                    r.mitre_technique_id, r.mitre_technique_name, r.mitre_tactic
                ))

        if parent_name in ("chrome.exe", "msedge.exe", "firefox.exe", "brave.exe") and name in ("cmd.exe", "powershell.exe", "certutil.exe", "bitsadmin.exe"):
            r = self.rules.rules.get("R-PARENT-02")
            if r and r.enabled:
                indicators.append(Indicator(
                    r.id, r.name, r.category, r.weight,
                    f"Browser '{parent_name}' spawned interpreter '{name}'",
                    f"PID {pid} parent PID {ppid}", "High",
                    r.mitre_technique_id, r.mitre_technique_name, r.mitre_tactic
                ))

        if name in self.rules.EXPECTED_PARENTS:
            expected = self.rules.EXPECTED_PARENTS[name]
            if parent_name and parent_name not in expected:
                r = self.rules.rules.get("R-PARENT-03")
                if r and r.enabled:
                    indicators.append(Indicator(
                        r.id, r.name, r.category, r.weight,
                        f"System binary '{name}' spawned by abnormal parent '{parent_name}' (expected: {expected})",
                        f"PPID {ppid} ({parent_name})", "High",
                        r.mitre_technique_id, r.mitre_technique_name, r.mitre_tactic
                    ))

        # 2. Path anomalies
        if name in self.rules.EXPECTED_SYSTEM_PATHS and path:
            expected_p = self.rules.EXPECTED_SYSTEM_PATHS[name].lower()
            if not path.startswith(r"c:\windows\system32") and not path.startswith(r"c:\windows\syswow64") and not path.startswith(r"c:\windows"):
                r = self.rules.rules.get("R-PATH-01")
                if r and r.enabled:
                    indicators.append(Indicator(
                        r.id, r.name, r.category, r.weight,
                        f"System binary '{name}' running from non-standard location: {path}",
                        f"Path: {path}", "High",
                        r.mitre_technique_id, r.mitre_technique_name, r.mitre_tactic
                    ))

        if any(bad in path for bad in (r"\temp", r"\appdata", r"\users\public", r"\recycle")):
            r = self.rules.rules.get("R-PATH-02")
            if r and r.enabled:
                indicators.append(Indicator(
                    r.id, r.name, r.category, r.weight,
                    f"Execution from user temp/appdata path",
                    f"Path: {path}", "Medium",
                    r.mitre_technique_id, r.mitre_technique_name, r.mitre_tactic
                ))

        # 3. Masquerading
        for target in self.rules.TYPOSQUAT_TARGETS:
            if name != target and 0 < len(name) <= len(target) + 2:
                if name.replace("0", "o").replace("1", "l") == target:
                    r = self.rules.rules.get("R-MASQ-01")
                    if r and r.enabled:
                        indicators.append(Indicator(
                            r.id, r.name, r.category, r.weight,
                            f"Process name '{name}' resembles system binary '{target}'",
                            f"Image: {name}", "High",
                            r.mitre_technique_id, r.mitre_technique_name, r.mitre_tactic
                        ))
                        break

        # 4. Hidden processes (DKOM)
        if process.get("in_psscan") and not process.get("in_pslist"):
            r = self.rules.rules.get("R-HIDDEN-01")
            if r and r.enabled:
                indicators.append(Indicator(
                    r.id, r.name, r.category, r.weight,
                    "Process unlinked from active process list (DKOM rootkit anomaly)",
                    "Present in psscan pool tags, absent from active pslist double-linked list", "High",
                    r.mitre_technique_id, r.mitre_technique_name, r.mitre_tactic
                ))

        # 5. Singleton processes
        if name in self.rules.SINGLETON_PROCESSES:
            count = sum(1 for p in all_processes if (p.get("name") or "").lower() == name)
            if count > 1:
                r = self.rules.rules.get("R-MULTI-01")
                if r and r.enabled:
                    indicators.append(Indicator(
                        r.id, r.name, r.category, r.weight,
                        f"Multiple instances ({count}) of singleton system process '{name}'",
                        f"{count} instances active", "High",
                        r.mitre_technique_id, r.mitre_technique_name, r.mitre_tactic
                    ))

        # 6. Command line flags
        if name in ("powershell.exe", "pwsh.exe") and any(f in cmd for f in ("-enc", "-encodedcommand", "-e ")):
            r = self.rules.rules.get("R-CMD-01")
            if r and r.enabled:
                indicators.append(Indicator(
                    r.id, r.name, r.category, r.weight,
                    "Encoded Base64 PowerShell execution",
                    f"Command: {cmd[:100]}...", "High",
                    r.mitre_technique_id, r.mitre_technique_name, r.mitre_tactic
                ))

        suspicious_terms = ["mimikatz", "procdump", "lsadump", "sekurlsa", "invoke-expression", "downloadstring", "bypass", "wmic process call"]
        if any(term in cmd for term in suspicious_terms):
            r = self.rules.rules.get("R-CMD-02")
            if r and r.enabled:
                indicators.append(Indicator(
                    r.id, r.name, r.category, r.weight,
                    "Suspicious security bypass/recon tooling in command line",
                    f"Args: {cmd[:100]}...", "Medium",
                    r.mitre_technique_id, r.mitre_technique_name, r.mitre_tactic
                ))

        # 7. Network connections (external sockets)
        proc_conns = [c for c in network_connections if c.get("pid") == pid]
        if proc_conns:
            ext_conns = [
                c for c in proc_conns
                if not str(c.get("remote_addr", "")).startswith(("10.", "192.168.", "172.16.", "127.", "0.", "::", "*"))
                and c.get("remote_addr") not in ("0.0.0.0", "127.0.0.1", "")
            ]
            if ext_conns:
                r = self.rules.rules.get("R-NET-01")
                if r and r.enabled:
                    indicators.append(Indicator(
                        r.id, r.name, r.category, r.weight,
                        f"Established {len(ext_conns)} socket(s) to public external IP(s)",
                        f"Remote: {ext_conns[0].get('remote_addr')}:{ext_conns[0].get('remote_port')}", "Medium",
                        r.mitre_technique_id, r.mitre_technique_name, r.mitre_tactic
                    ))

        # 8. Memory injection (RWX regions)
        proc_mem = [m for m in memory_anomalies if m.get("pid") == pid]
        if proc_mem:
            rwx_mem = [
                m for m in proc_mem
                if not m.get("protection")
                or any(x in (m.get("protection") or "").upper() for x in ("EXECUTE_READWRITE", "EXECUTE_WRITECOPY", "RWX"))
                or ("EXECUTE" in (m.get("protection") or "").upper() and "WRITE" in (m.get("protection") or "").upper())
            ]
            r = self.rules.rules.get("R-MEM-01")
            if r and r.enabled:
                if rwx_mem:
                    indicators.append(Indicator(
                        r.id, r.name, r.category, r.weight,
                        f"Found {len(rwx_mem)} confirmed RWX executable/writable memory region(s) (Malfind)",
                        f"Address: {rwx_mem[0].get('start_address')}, Protection: {rwx_mem[0].get('protection')}", "High",
                        r.mitre_technique_id, r.mitre_technique_name, r.mitre_tactic
                    ))
                else:
                    indicators.append(Indicator(
                        r.id, r.name, r.category, max(15, r.weight // 2),
                        f"Found {len(proc_mem)} executable memory anomaly region(s) (Protection: {proc_mem[0].get('protection', 'Unknown')})",
                        f"Address: {proc_mem[0].get('start_address')}", "Medium",
                        r.mitre_technique_id, r.mitre_technique_name, r.mitre_tactic
                    ))

        # Calculate final 0-100 score
        total_score = min(100, sum(ind.weight for ind in indicators))

        # Strict DFIR threshold classification
        if total_score >= RISK_THRESHOLD_CRITICAL:
            level = "Critical"
            severity = "Critical"
        elif total_score >= RISK_THRESHOLD_HIGH:
            level = "High"
            severity = "High"
        elif total_score >= RISK_THRESHOLD_SUSPICIOUS:
            level = "Suspicious"
            severity = "Medium"
        else:
            level = "Normal"
            severity = "Normal"

        # Overall confidence based on highest confidence indicator
        if any(ind.confidence == "High" for ind in indicators):
            confidence = "High"
        elif any(ind.confidence == "Medium" for ind in indicators):
            confidence = "Medium"
        elif indicators:
            confidence = "Low"
        else:
            confidence = "Medium"

        # Build explainable rationale
        if indicators:
            reasons = [ind.reason for ind in indicators]
            explanation = f"Process flagged as {level} (Risk Score: {total_score}/100) based on {len(indicators)} heuristic detection(s): " + "; ".join(reasons)
        else:
            explanation = "No suspicious behavioral heuristics or memory anomalies detected for this process."

        # Generate First-Class Detection records
        detections: List[Detection] = []
        for ind in indicators:
            det = Detection(
                id=str(uuid.uuid4()),
                case_id=case_id,
                evidence_id=evidence_id,
                rule_id=ind.rule_id,
                rule_name=ind.rule_name,
                category=ind.category,
                severity=level if level in ("Critical", "High") else "Medium",
                confidence=ind.confidence,
                affected_entity=f"PID {pid} ({process.get('name', 'unknown')})",
                entity_type="process",
                explanation=ind.reason,
                contributing_factors=f"Weight: {ind.weight}. Evidence: {ind.evidence_text}",
                supporting_artifacts=ind.evidence_text,
                mitre_technique_id=ind.mitre_technique_id,
                mitre_technique_name=ind.mitre_technique_name,
                mitre_tactic=ind.mitre_tactic,
                created_at=datetime.now().isoformat()
            )
            detections.append(det)

        return {
            "pid": pid,
            "risk_score": total_score,
            "risk_level": level,
            "confidence": confidence,
            "severity": severity,
            "indicators": [
                {
                    "rule_id": ind.rule_id,
                    "rule_name": ind.rule_name,
                    "category": ind.category,
                    "weight": ind.weight,
                    "reason": ind.reason,
                    "evidence_text": ind.evidence_text,
                    "confidence": ind.confidence,
                    "mitre_technique_id": ind.mitre_technique_id,
                    "mitre_technique_name": ind.mitre_technique_name,
                    "mitre_tactic": ind.mitre_tactic
                }
                for ind in indicators
            ],
            "explanation": explanation,
            "detections": [d.to_dict() for d in detections]
        }

    def evaluate_all(
        self,
        all_processes: List[Dict[str, Any]],
        network_connections: List[Dict[str, Any]],
        memory_anomalies: List[Dict[str, Any]],
        case_id: str = "",
        evidence_id: str = ""
    ) -> Dict[int, Dict[str, Any]]:
        """Evaluates risk across all processes and returns a mapping of PID -> evaluation result."""
        results = {}
        for p in all_processes:
            pid = p.get("pid", 0)
            res = self.evaluate_process(
                process=p,
                all_processes=all_processes,
                network_connections=network_connections,
                memory_anomalies=memory_anomalies,
                case_id=case_id,
                evidence_id=evidence_id
            )
            results[pid] = res
        return results
