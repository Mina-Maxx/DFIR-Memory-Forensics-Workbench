"""
Pure-Python WebBridge for DFIR Workbench.
Provides bidirectional slot calling and signal emission for the web browser frontend,
with zero dependencies on Qt or PySide6.
"""
import os
import sys
import uuid
import json
import csv
import hashlib
import threading
from typing import Optional, Dict, Any, List, Callable

from core.database import DatabaseManager
from core.case_manager import CaseManager
from core.evidence_manager import EvidenceManager
from core.job_manager import JobManager
from core.investigation_engine import InvestigationEngine
from core.ioc_engine import IOCEngine
from core.timeline_engine import TimelineEngine
from core.report_engine import ReportEngine
from core.diff_engine import diff_evidence
from core.graph_builder import build_graph
from core.playbook_engine import PlaybookEngine
from core.yara_engine import YaraEngine
from core.rule_engine import RuleEngine
from core.models import Finding, IOC, DumpArtifact
from core import report_exporters
from forensics.plugin_discovery import PluginDiscovery
from forensics.vol_adapter import VolAdapter
from core.logger import get_logger

logger = get_logger("app")


class PureSignal:
    """Thread-safe signal mechanism replacing PySide6.QtCore.Signal."""
    def __init__(self, name: str):
        self.name = name
        self._subscribers: List[Callable] = []
        self._lock = threading.Lock()

    def connect(self, callback: Callable):
        with self._lock:
            if callback not in self._subscribers:
                self._subscribers.append(callback)

    def disconnect(self, callback: Callable):
        with self._lock:
            if callback in self._subscribers:
                self._subscribers.remove(callback)

    def emit(self, *args):
        with self._lock:
            cbs = list(self._subscribers)
        for cb in cbs:
            try:
                cb(*args)
            except Exception as e:
                logger.debug(f"Signal {self.name} delivery error: {e}")


class WebBridge:
    """Pure-Python Bridge matching all slots and signals of DFIRBridge for web mode."""

    def __init__(
        self,
        db: DatabaseManager,
        case_mgr: CaseManager,
        evidence_mgr: EvidenceManager,
        job_mgr: JobManager,
        inv_engine: InvestigationEngine,
        ioc_engine: IOCEngine,
        tl_engine: TimelineEngine,
        rep_engine: ReportEngine,
        discovery: PluginDiscovery,
        vol_adapter: VolAdapter,
        playbook_engine: Optional[PlaybookEngine] = None,
        yara_engine: Optional[YaraEngine] = None,
        rule_engine: Optional[RuleEngine] = None
    ):
        self.db = db
        self.case_mgr = case_mgr
        self.evidence_mgr = evidence_mgr
        self.job_mgr = job_mgr
        self.inv_engine = inv_engine
        self.ioc_engine = ioc_engine
        self.tl_engine = tl_engine
        self.rep_engine = rep_engine
        self.discovery = discovery
        self.vol_adapter = vol_adapter
        self.playbook_engine = playbook_engine or PlaybookEngine(job_mgr)
        self.yara_engine = yara_engine or YaraEngine(db)
        self.rule_engine = rule_engine or RuleEngine()

        self.active_case_id: Optional[str] = None
        self.active_evidence_id: Optional[str] = None
        self.active_evidence_path: Optional[str] = None
        self._playbook_progress_text: str = ""

        # Bridge Signals
        self.job_started = PureSignal("job_started")
        self.job_activity = PureSignal("job_activity")
        self.job_finished = PureSignal("job_finished")
        self.results_ready = PureSignal("results_ready")
        self.triage_completed = PureSignal("triage_completed")
        self.log_emitted = PureSignal("log_emitted")
        self.hash_progress = PureSignal("hash_progress")
        self.playbook_progress = PureSignal("playbook_progress")
        self.playbook_finished = PureSignal("playbook_finished")

        # Wire JobManager events
        self.job_mgr.subscribe(self._on_job_event)
        self.playbook_engine.subscribe(self._on_playbook_event)

        # Auto-activate case with evidence if available
        cases = self.db.list_cases()
        active_case = None
        for c in cases:
            if self.db.list_evidence_for_case(c.id):
                active_case = c
                break
        if not active_case and cases:
            active_case = cases[0]

        if active_case:
            self.active_case_id = active_case.id
            evs = self.db.list_evidence_for_case(active_case.id)
            if evs:
                self.active_evidence_id = evs[0].id
                self.active_evidence_path = evs[0].filepath

    def _on_playbook_event(self, msg: str):
        self._playbook_progress_text = msg
        self.playbook_progress.emit(msg)
        if "finished" in msg.lower() or "completed" in msg.lower():
            self.playbook_finished.emit(msg)

    def _on_job_event(self, event: str, data: Dict[str, Any]):
        if event == "job_started":
            eid = data.get("execution_id", "")
            pname = data.get("plugin_name", "")
            self.job_started.emit(eid, pname)
            self.log_emitted.emit("INFO", f"Job started: {pname} [{eid}]")

        elif event == "job_activity":
            eid = data.get("execution_id", "")
            act = data.get("activity", "")
            self.job_activity.emit(eid, act)

        elif event == "job_finished":
            eid = data.get("execution_id", "")
            pname = data.get("plugin_name", "")
            ok = (data.get("status") == "Completed")
            err = data.get("error", "")
            self.job_finished.emit(eid, ok, err if not ok else "Completed")
            self.log_emitted.emit("INFO" if ok else "ERROR", f"Job [{eid}] {'COMPLETED' if ok else 'FAILED'}: {pname}")

            # Emit results ready
            self.results_ready.emit(eid, pname)

            # Auto-correlate on critical forensic plugins
            ev_id = data.get("evidence_id") or self.active_evidence_id
            if ok and ev_id:
                crit = ("pslist", "psscan", "pstree", "netscan", "malfind", "cmdline")
                if any(c in pname.lower() for c in crit):
                    try:
                        self.inv_engine.correlate_evidence(ev_id)
                        self.tl_engine.generate_timeline(self.active_case_id or "", ev_id)
                        if "netscan" in pname.lower() and self.active_case_id:
                            self.ioc_engine.harvest_from_network(self.active_case_id, ev_id)
                    except Exception as e:
                        logger.error(f"Auto-correlation on job completion failed: {e}")

        elif event == "triage_completed":
            ev_id = data.get("evidence_id") or self.active_evidence_id or ""
            try:
                self.inv_engine.correlate_evidence(ev_id)
                self.tl_engine.generate_timeline(self.active_case_id or "", ev_id)
                if self.active_case_id:
                    self.ioc_engine.harvest_from_network(self.active_case_id, ev_id)
            except Exception as e:
                logger.error(f"Post-triage correlation error: {e}")
            self.triage_completed.emit(ev_id)
            self.log_emitted.emit("INFO", f"Automated triage and correlation completed for Evidence {ev_id}!")

    # -------------------------------------------------------------
    # CASE MANAGEMENT SLOTS
    # -------------------------------------------------------------
    def list_cases(self) -> str:
        cases = self.case_mgr.list_cases()
        return json.dumps([c.to_dict() for c in cases])

    def create_case(self, case_id: str, name: str, investigator: str, description: str) -> str:
        try:
            base_cid = (case_id or "").strip() or f"DFIR-{uuid.uuid4().hex[:8].upper()}"
            cid = base_cid
            n = 1
            while self.case_mgr.load_case(cid):
                n += 1
                cid = f"{base_cid}-{n}"

            case = self.case_mgr.create_case(cid, name, investigator, description)
            self.active_case_id = case.id
            self.active_evidence_id = None
            self.active_evidence_path = None
            self.log_emitted.emit("INFO", f"Case created: {case.name} ({case.id})")
            return json.dumps({"success": True, "case": case.to_dict()})
        except Exception as e:
            logger.error(f"Error creating case: {e}")
            return json.dumps({"success": False, "error": str(e)})

    def open_case(self, case_id: str) -> str:
        case = self.case_mgr.load_case(case_id)
        if case:
            self.active_case_id = case.id
            evs = self.db.list_evidence_for_case(case.id)
            if evs:
                self.active_evidence_id = evs[0].id
                self.active_evidence_path = evs[0].filepath
            else:
                self.active_evidence_id = None
                self.active_evidence_path = None
            self.log_emitted.emit("INFO", f"Case opened: {case.name} ({case.id})")
            return json.dumps({"success": True, "case": case.to_dict()})
        return json.dumps({"success": False, "error": "Case not found"})

    def get_active_case_id(self) -> Optional[str]:
        return self.active_case_id

    def get_active_evidence_id(self) -> Optional[str]:
        return self.active_evidence_id

    def set_active_case(self, case_id: str) -> bool:
        res = json.loads(self.open_case(case_id))
        return bool(res.get("success", False))

    def get_active_case(self) -> str:
        if self.active_case_id:
            case = self.case_mgr.load_case(self.active_case_id)
            if case:
                return json.dumps(case.to_dict())
        return json.dumps(None)

    def delete_case(self, case_id: str, delete_files: bool = False) -> str:
        success = self.case_mgr.delete_case(case_id, delete_files=delete_files)
        if success:
            if self.active_case_id == case_id:
                cases = self.case_mgr.list_cases()
                self.active_case_id = cases[0].id if cases else None
                self.active_evidence_id = None
                self.active_evidence_path = None
            self.log_emitted.emit("INFO", f"Case deleted: {case_id}")
            return json.dumps({"success": True})
        return json.dumps({"success": False, "error": "Failed to delete case"})

    # -------------------------------------------------------------
    # EVIDENCE MANAGEMENT SLOTS
    # -------------------------------------------------------------
    def prompt_import_evidence(self) -> str:
        return json.dumps({"success": False, "mode": "web"})

    def import_evidence_path(self, filepath: str, case_id: str = "") -> str:
        cid = case_id or self.active_case_id
        if not cid:
            return json.dumps({"success": False, "error": "Please open or create a case first."})
        if not filepath or not os.path.exists(filepath):
            return json.dumps({"success": False, "error": f"File not found: {filepath}"})

        try:
            def update_cb(pct):
                self.hash_progress.emit(pct)

            sha256, md5 = self.evidence_mgr.compute_hashes_sync(filepath, update_cb)
            ev = self.evidence_mgr.import_evidence(cid, filepath, sha256, md5)
            self.active_evidence_id = ev.id
            self.active_evidence_path = ev.filepath
            self.log_emitted.emit("INFO", f"Imported memory evidence: {ev.filename} ({ev.file_size:,} bytes)")
            return json.dumps({"success": True, "evidence": ev.to_dict()})
        except Exception as e:
            logger.error(f"Error importing evidence: {e}")
            return json.dumps({"success": False, "error": str(e)})

    def list_evidence(self, case_id: str = "") -> str:
        cid = case_id or self.active_case_id or ""
        evidence_list = self.evidence_mgr.list_evidence(cid)
        return json.dumps([e.to_dict() for e in evidence_list])

    def set_active_evidence(self, evidence_id: str) -> str:
        ev = self.evidence_mgr.get_evidence(evidence_id)
        if not ev:
            return json.dumps({"success": False, "error": "Evidence not found."})
        if self.active_case_id and ev.case_id != self.active_case_id:
            self.active_case_id = ev.case_id

        self.active_evidence_id = ev.id
        self.active_evidence_path = ev.filepath
        self.log_emitted.emit("INFO", f"Active evidence set to: {ev.filename}")
        return json.dumps({"success": True, "evidence": ev.to_dict()})

    def get_active_evidence(self) -> str:
        if self.active_evidence_id:
            ev = self.evidence_mgr.get_evidence(self.active_evidence_id)
            if ev:
                return json.dumps(ev.to_dict())
        return json.dumps(None)

    def verify_evidence_hash(self, evidence_id: str) -> str:
        res = self.evidence_mgr.verify_integrity(evidence_id)
        return json.dumps(res)

    def delete_evidence(self, evidence_id: str) -> str:
        if not evidence_id:
            return json.dumps({"success": False, "error": "No evidence ID specified"})
        ok = self.evidence_mgr.delete_evidence(evidence_id)
        if ok:
            if self.active_evidence_id == evidence_id:
                self.active_evidence_id = None
                self.active_evidence_path = None
            self.log_emitted.emit("INFO", f"Deleted evidence: {evidence_id}")
            return json.dumps({"success": True})
        return json.dumps({"success": False, "error": "Failed to delete evidence"})

    # -------------------------------------------------------------
    # PLUGIN & JOB SLOTS
    # -------------------------------------------------------------
    def list_plugins(self) -> str:
        categories = self.discovery.discover_all()
        result = {}
        for cat, plist in categories.items():
            result[cat] = [
                {
                    "name": p.name if hasattr(p, "name") else p.get("name", ""),
                    "doc": p.doc if hasattr(p, "doc") else p.get("description", p.get("doc", "")),
                    "category": p.category if hasattr(p, "category") else p.get("category", "General"),
                    "os_type": p.os_type if hasattr(p, "os_type") else p.get("os_type", cat),
                    "requirements": p.requirements if hasattr(p, "requirements") else p.get("requirements", [])
                }
                for p in plist
            ]
        return json.dumps(result)

    def run_plugin(self, plugin_name: str, args_json: str = "[]") -> str:
        if not self.active_evidence_id:
            return json.dumps({"success": False, "error": "No memory evidence selected."})

        try:
            extra_args = json.loads(args_json) if isinstance(args_json, str) else (args_json or [])
        except Exception:
            extra_args = []

        try:
            ex = self.job_mgr.run_plugin(self.active_evidence_id, plugin_name, extra_args)
            return json.dumps({"success": True, "execution_id": ex.id})
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    def cancel_job(self, execution_id: str) -> str:
        cancelled = self.job_mgr.cancel_job(execution_id)
        return json.dumps({"success": cancelled})

    def list_executions(self, evidence_id: str = "") -> str:
        eid = evidence_id or self.active_evidence_id
        executions = self.db.list_executions(eid)
        return json.dumps([ex.to_dict() for ex in executions])

    def get_execution_results(self, execution_id: str) -> str:
        row = self.db.get_result(execution_id)
        if not row:
            return json.dumps({"headers": [], "data": []})

        headers = json.loads(row.headers) if row.headers else []
        if row.storage_mode == "file" and row.file_path and os.path.exists(row.file_path):
            try:
                with open(row.file_path, "r", encoding="utf-8") as f:
                    file_content = json.load(f)
                    data = file_content.get("data", []) if isinstance(file_content, dict) else file_content
                    headers = file_content.get("headers", headers) if isinstance(file_content, dict) else headers
            except Exception:
                data = json.loads(row.data) if row.data else []
        else:
            data = json.loads(row.data) if row.data else []

        return json.dumps({"headers": headers, "data": data, "row_count": row.row_count})

    def start_automated_triage(self, evidence_id: str = "") -> str:
        eid = evidence_id or self.active_evidence_id
        if not eid and self.db:
            try:
                row = self.db._get_conn().execute("SELECT id FROM evidence ORDER BY created_at DESC LIMIT 1").fetchone()
                if row:
                    eid = row["id"]
            except Exception:
                pass

        if not eid:
            return json.dumps({"success": False, "error": "No memory evidence selected. Please import or select a memory dump first."})

        self.active_evidence_id = eid
        ev = self.db.get_evidence(eid)
        if ev and ev.case_id:
            self.active_case_id = ev.case_id

        self.log_emitted.emit("INFO", f"Starting automated triage on evidence {eid}")
        plugins = self.job_mgr.start_automated_triage(eid)
        return json.dumps({"success": True, "plugins": plugins})

    # -------------------------------------------------------------
    # PROCESSES & INVESTIGATION SLOTS
    # -------------------------------------------------------------
    def get_correlated_processes(self, evidence_id: str = "") -> str:
        eid = evidence_id or self.active_evidence_id
        if not eid:
            return json.dumps([])
        procs = self.db.list_processes(eid)
        return json.dumps([p.to_dict() for p in procs])

    def get_process_by_record_id(self, process_id: str) -> str:
        if not process_id:
            return json.dumps(None)
        p = self.db.get_process(process_id)
        if not p:
            return json.dumps(None)
        d = p.to_dict()
        conns = [c.to_dict() for c in self.db.list_connections(p.evidence_id) if c.pid == p.pid]
        d["network_connections"] = conns
        return json.dumps(d)

    def get_process_detail(self, evidence_id: str, pid: int) -> str:
        eid = evidence_id or self.active_evidence_id
        if not eid:
            return json.dumps(None)

        procs = self.db.list_processes(eid)
        for p in procs:
            if p.pid == pid:
                d = p.to_dict()
                conns = [c.to_dict() for c in self.db.list_connections(eid) if c.pid == pid]
                d["network_connections"] = conns
                d["connections"] = conns
                d["dlls"] = []
                d["memory_regions"] = []
                return json.dumps({"process": d, "connections": conns, "dlls": [], "memory_regions": []})

        correlated = self.inv_engine.correlate_evidence(eid)
        if pid in correlated:
            cp = correlated[pid].to_dict()
            conns = [c.to_dict() for c in self.db.list_connections(eid) if c.pid == pid]
            cp["network_connections"] = conns
            cp["connections"] = conns
            cp["dlls"] = []
            cp["memory_regions"] = []
            return json.dumps({"process": cp, "connections": conns, "dlls": [], "memory_regions": []})

        return json.dumps(None)

    def get_network_connections(self, evidence_id: str = "") -> str:
        eid = evidence_id or self.active_evidence_id
        if not eid:
            return json.dumps([])
        conns = self.db.list_connections(eid)
        return json.dumps([c.to_dict() for c in conns])

    # -------------------------------------------------------------
    # DUMP ARTIFACTS SLOTS
    # -------------------------------------------------------------
    def record_dump(self, case_id: str, evidence_id: str, dump_type: str,
                    output_path: str, pid: int = 0, address: str = "") -> str:
        cid = case_id or self.active_case_id or "CASE-001"
        eid = evidence_id or self.active_evidence_id or "EV-001"
        if not os.path.exists(output_path):
            return json.dumps({"success": False, "error": f"Target dump file does not exist: {output_path}"})
        if os.path.getsize(output_path) == 0:
            return json.dumps({"success": False, "error": f"Target dump file is empty: {output_path}"})

        try:
            artifact = self.evidence_mgr.record_dump_artifact(
                case_id=cid,
                evidence_id=eid,
                dump_type=dump_type,
                output_path=os.path.abspath(output_path),
                source_plugin="windows.dumpfiles",
                pid=pid,
                address=address
            )
            return json.dumps({"success": True, "artifact": artifact.to_dict()})
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    def extract_process_dump(self, case_id: str, evidence_id: str, pid: int) -> str:
        cid = case_id or self.active_case_id
        eid = evidence_id or self.active_evidence_id
        if not cid or not eid:
            return json.dumps({"success": False, "error": "No active case or evidence selected."})

        case = self.case_mgr.load_case(cid)
        ev = self.evidence_mgr.get_evidence(eid)
        if not case or not ev:
            return json.dumps({"success": False, "error": "Case or evidence record not found."})

        dumps_dir = os.path.join(case.workspace_path, "dumps")
        os.makedirs(dumps_dir, exist_ok=True)
        existing_files = set(os.listdir(dumps_dir))

        self.log_emitted.emit("INFO", f"Executing memory dump extraction for PID {pid} via windows.dumpfiles...")
        self.vol_adapter.execute_plugin(
            ev.filepath,
            "windows.dumpfiles.DumpFiles",
            ["--pid", str(pid)],
            output_dir=dumps_dir
        )

        current_files = set(os.listdir(dumps_dir))
        new_files = current_files - existing_files
        source_plugin = "windows.dumpfiles"

        if not new_files:
            self.log_emitted.emit("INFO", f"Trying address space page dump for PID {pid} via windows.memmap...")
            self.vol_adapter.execute_plugin(
                ev.filepath,
                "windows.memmap.Memmap",
                ["--dump", "--pid", str(pid)],
                output_dir=dumps_dir
            )
            current_files = set(os.listdir(dumps_dir))
            new_files = current_files - existing_files
            source_plugin = "windows.memmap"

        if not new_files:
            return json.dumps({
                "success": False,
                "error": f"Volatility did not produce dump files for PID {pid}. Check if process has mapped memory."
            })

        recorded_artifacts = []
        for nf in new_files:
            fpath = os.path.join(dumps_dir, nf)
            if os.path.isfile(fpath) and os.path.getsize(fpath) > 0:
                art = self.evidence_mgr.record_dump_artifact(
                    case_id=cid,
                    evidence_id=eid,
                    dump_type="process",
                    output_path=fpath,
                    source_plugin=source_plugin,
                    pid=pid,
                    address="0x0"
                )
                recorded_artifacts.append(art.to_dict())
                self.log_emitted.emit("INFO", f"Dump artifact recorded: {nf} (SHA-256: {art.sha256[:16]}...)")

        return json.dumps({"success": True, "count": len(recorded_artifacts), "artifacts": recorded_artifacts})

    def list_dump_artifacts(self, case_id: str = "", evidence_id: str = "") -> str:
        cid = case_id or self.active_case_id
        eid = evidence_id or self.active_evidence_id
        dumps = self.db.list_dump_artifacts(cid, eid)
        return json.dumps([d.to_dict() for d in dumps])

    def delete_dump_artifact(self, artifact_id: str) -> str:
        ok = self.db.delete_dump_artifact(artifact_id)
        if ok:
            self.log_emitted.emit("INFO", f"Deleted dump artifact: {artifact_id}")
        return json.dumps({"success": ok})

    def verify_dump_artifact(self, artifact_id: str) -> str:
        a = self.db.get_dump_artifact(artifact_id)
        if not a:
            return json.dumps({"success": False, "error": "Artifact not found"})
        d = a.to_dict() if hasattr(a, "to_dict") else dict(a)
        path = d.get("output_path")
        if not path or not os.path.isfile(path):
            return json.dumps({"success": False, "error": "File missing"})

        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(4 * 1024 * 1024), b""):
                h.update(chunk)
        ok = h.hexdigest() == (d.get("sha256") or "")
        return json.dumps({"success": True, "verified": ok})

    # -------------------------------------------------------------
    # IOC & HUNT SLOTS
    # -------------------------------------------------------------
    def list_iocs(self, case_id: str = "") -> str:
        cid = case_id or self.active_case_id or ""
        iocs = self.ioc_engine.list_iocs(cid)
        return json.dumps([i.to_dict() for i in iocs])

    def add_ioc(self, case_id: str, ioc_type: str, value: str, severity: str,
                description: str = "", pid: int = 0) -> str:
        cid = case_id or self.active_case_id or "CASE-001"
        try:
            ioc = self.ioc_engine.add_ioc(cid, ioc_type, value, severity, "Analyst Manual", description, pid)
            return json.dumps({"success": True, "ioc": ioc.to_dict()})
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    def delete_ioc(self, ioc_id: str) -> str:
        ok = self.db.delete_ioc(ioc_id)
        if ok:
            self.log_emitted.emit("INFO", f"Deleted IOC: {ioc_id}")
        return json.dumps({"success": ok})

    def hunt_ioc(self, query: str, evidence_id: str = "") -> str:
        eid = evidence_id or self.active_evidence_id
        if not eid:
            return json.dumps([])
        results = self.ioc_engine.hunt(query, eid)
        return json.dumps(results)

    # -------------------------------------------------------------
    # TIMELINE SLOTS
    # -------------------------------------------------------------
    def get_timeline(self, evidence_id: str = "", filter_type: str = "ALL", query: str = "") -> str:
        eid = evidence_id or self.active_evidence_id
        if not eid:
            return json.dumps([])
        events = self.tl_engine.get_events(eid, filter_type=filter_type, search_query=query)
        return json.dumps([e.to_dict() for e in events])

    # -------------------------------------------------------------
    # FINDINGS & REPORTS SLOTS
    # -------------------------------------------------------------
    def list_findings(self, case_id: str = "") -> str:
        cid = case_id or self.active_case_id or ""
        findings = self.db.list_findings(cid)
        return json.dumps([f.to_dict() for f in findings])

    def delete_finding(self, finding_id: str) -> str:
        ok = self.db.delete_finding(finding_id)
        if ok:
            self.log_emitted.emit("INFO", f"Deleted finding: {finding_id}")
        return json.dumps({"success": ok})

    def create_finding(self, case_id: str, title: str, severity: str, desc: str,
                       pid: int = 0, proc: str = "", assessment: str = "") -> str:
        cid = case_id or self.active_case_id or "CASE-001"
        f = Finding(
            case_id=cid,
            title=title,
            severity=severity,
            description=desc,
            associated_pid=pid if pid > 0 else 0,
            associated_process_name=proc,
            analyst_assessment=assessment
        )
        self.db.create_finding(f)
        return json.dumps({"success": True, "finding": f.to_dict()})

    def generate_report(self, case_id: str = "") -> str:
        cid = case_id or self.active_case_id
        if not cid:
            return json.dumps({"success": False, "error": "No active case"})
        case = self.case_mgr.load_case(cid)
        if not case:
            return json.dumps({"success": False, "error": "Case not found"})

        out_path = os.path.join(case.workspace_path, "exports", f"Report_{case.id}.html")
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        try:
            report_content = self.rep_engine.generate_html_report(cid, out_path)
            if not report_content and os.path.exists(out_path):
                with open(out_path, "r", encoding="utf-8", errors="replace") as f:
                    report_content = f.read()
            return json.dumps({"success": True, "path": out_path, "report_html": report_content})
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    def open_path_in_browser(self, path: str) -> bool:
        import webbrowser
        if not path:
            return False
        abs_path = os.path.abspath(path)
        allowed_exts = {".html", ".htm", ".pdf", ".txt", ".json", ".csv"}
        _, ext = os.path.splitext(abs_path)
        if ext.lower() not in allowed_exts:
            logger.warning(f"open_path_in_browser blocked execution of disallowed extension: {ext}")
            return False
        if os.path.exists(abs_path):
            webbrowser.open(f"file://{abs_path}")
            return True
        return False

    def get_live_state(self) -> str:
        """Lightweight live polling endpoint for UI status tickers."""
        jobs = []
        try:
            rows = self.db.list_executions()
            for ex in rows[-15:]:
                d = ex.to_dict() if hasattr(ex, "to_dict") else dict(ex)
                jobs.append({
                    "id": d.get("id"),
                    "plugin": d.get("plugin_name"),
                    "status": d.get("status"),
                    "activity": d.get("current_activity") or "",
                    "runtime": d.get("runtime_seconds"),
                    "rows": d.get("result_count"),
                    "start_time": d.get("start_time"),
                })
        except Exception as e:
            logger.error(f"live_state jobs error: {e}")

        pb = getattr(self, "_playbook_progress_text", "")
        pb_running = False
        try:
            if hasattr(self, "playbook_engine"):
                pb_running = self.playbook_engine.is_running
        except Exception:
            pass

        return json.dumps({
            "jobs": jobs,
            "running": any(j["status"] == "Running" for j in jobs),
            "playbook_running": pb_running,
            "playbook_progress": pb
        })

    # -------------------------------------------------------------
    # PLAYBOOKS, GRAPH, DIFF, YARA, EXPORTS SLOTS
    # -------------------------------------------------------------
    def list_playbooks(self) -> str:
        return json.dumps(self.playbook_engine.list_playbooks())

    def run_playbook(self, playbook_id: str) -> str:
        if not self.active_evidence_id:
            return json.dumps({"success": False, "error": "No memory evidence selected."})
        if self.playbook_engine.is_running:
            return json.dumps({"success": False, "error": "A playbook is already running."})

        ok = self.playbook_engine.run_playbook(playbook_id, self.active_evidence_id)
        return json.dumps({"success": bool(ok)})

    def get_graph_data(self, evidence_id: str = "") -> str:
        eid = evidence_id or self.active_evidence_id
        if not eid:
            return json.dumps({"nodes": [], "edges": [], "stats": {}})
        try:
            data = build_graph(self.db, eid)
            return json.dumps(data)
        except Exception as e:
            logger.error(f"Graph build failed: {e}")
            return json.dumps({"nodes": [], "edges": [], "error": str(e)})

    def diff_evidences(self, ev_a: str, ev_b: str) -> str:
        if not ev_a or not ev_b:
            return json.dumps({"success": False, "error": "Two evidence IDs required"})
        try:
            raw = diff_evidence(self.db, ev_a, ev_b)
            pa = [p.to_dict() if hasattr(p, "to_dict") else p for p in self.db.list_processes(ev_a)]
            pb = [p.to_dict() if hasattr(p, "to_dict") else p for p in self.db.list_processes(ev_b)]
            kb = {(p.get("pid"), (p.get("name") or "").lower()) for p in pb}
            common = [p for p in pa if (p.get("pid"), (p.get("name") or "").lower()) in kb]

            diff_obj = {
                "new_processes": raw.get("processes", {}).get("added", []),
                "terminated_processes": raw.get("processes", {}).get("removed", []),
                "common_processes": common,
                "processes": raw.get("processes", {}),
                "network": raw.get("network", {}),
                "indicator_changes": raw.get("indicator_changes", []),
                "counts": raw.get("counts", {})
            }
            return json.dumps({"success": True, "diff": diff_obj})
        except Exception as e:
            logger.error(f"Diff execution failed: {e}")
            return json.dumps({"success": False, "error": str(e)})

    def yara_available(self) -> bool:
        from core.yara_engine import available
        return available()

    def yara_validate(self, rule_path: str) -> str:
        from core.yara_engine import validate_rule_file
        return json.dumps({"error": validate_rule_file(rule_path)})

    def prompt_yara_file(self) -> str:
        return ""

    def run_yara_scan(self, rule_path: str) -> str:
        from core.yara_engine import validate_rule_file
        if not self.active_evidence_id:
            return json.dumps({"success": False, "error": "No memory evidence selected."})
        err = validate_rule_file(rule_path)
        if err:
            return json.dumps({"success": False, "error": err})

        try:
            ex = self.job_mgr.run_plugin(
                self.active_evidence_id,
                "windows.vadyarascan.VadYaraScan",
                ["--yara-file", rule_path]
            )
            return json.dumps({"success": True, "execution_id": ex.id})
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    def get_yara_matches(self, evidence_id: str = "") -> str:
        eid = evidence_id or self.active_evidence_id
        return json.dumps(self.yara_engine.matches_for(eid) if eid else [])

    def export_report_pdf(self, case_id: str = "") -> str:
        cid = case_id or self.active_case_id
        if not cid:
            return json.dumps({"success": False, "error": "No active case"})
        case = self.case_mgr.load_case(cid)
        if not case:
            return json.dumps({"success": False, "error": "Case not found"})

        html_path = os.path.join(case.workspace_path, "exports", f"Report_{cid}.html")
        if not os.path.isfile(html_path):
            try:
                self.rep_engine.generate_html_report(cid, html_path)
            except Exception as e:
                return json.dumps({"success": False, "error": str(e)})

        pdf_path = html_path.replace(".html", ".pdf")
        return json.dumps({"success": True, "path": pdf_path, "html_path": html_path})

    def export_report_package(self, case_id: str = "") -> str:
        cid = case_id or self.active_case_id
        if not cid:
            return json.dumps({"success": False, "error": "No active case"})
        case = self.case_mgr.load_case(cid)
        if not case:
            return json.dumps({"success": False, "error": "Case not found"})
        try:
            out = report_exporters.export_package(self.db, cid, self.rep_engine, case.workspace_path)
            return json.dumps({"success": True, "path": out, "package_path": out})
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    def export_iocs_stix(self, case_id: str = "") -> str:
        cid = case_id or self.active_case_id
        if not cid:
            return json.dumps({"success": False, "error": "No active case"})
        case = self.case_mgr.load_case(cid)
        if not case:
            return json.dumps({"success": False, "error": "Case not found"})

        os.makedirs(os.path.join(case.workspace_path, "exports"), exist_ok=True)
        target = os.path.join(case.workspace_path, "exports", f"iocs_{cid}.stix.json")
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(report_exporters.build_stix(self.db.list_iocs(cid)))
        return json.dumps({"success": True, "path": target})

    def export_command_history(self, case_id: str = "") -> str:
        cid = case_id or self.active_case_id
        if not cid:
            return json.dumps({"success": False, "error": "No active case"})
        case = self.case_mgr.load_case(cid)
        if not case:
            return json.dumps({"success": False, "error": "Case not found"})

        os.makedirs(os.path.join(case.workspace_path, "exports"), exist_ok=True)
        target = os.path.join(case.workspace_path, "exports", f"command_history_{cid}.csv")
        with open(target, "w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["start", "end", "plugin", "args", "status", "rows", "command"])
            for x in self.db.list_executions():
                d = x.to_dict() if hasattr(x, "to_dict") else dict(x)
                if d.get("case_id") != cid:
                    continue
                def _sanitize(val):
                    s = str(val or "")
                    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
                        return "'" + s
                    return s
                writer.writerow([
                    _sanitize(d.get("start_time")),
                    _sanitize(d.get("end_time")),
                    _sanitize(d.get("plugin_name")),
                    _sanitize(d.get("arguments")),
                    _sanitize(d.get("status")),
                    d.get("result_count") or 0,
                    _sanitize(d.get("command")),
                ])
        return json.dumps({"success": True, "path": target})

    def open_exports_folder(self, case_id: str = "") -> str:
        cid = case_id or self.active_case_id
        case = self.case_mgr.load_case(cid) if cid else None
        if not case:
            return json.dumps({"success": False, "error": "No active case"})
        exports = os.path.join(case.workspace_path, "exports")
        os.makedirs(exports, exist_ok=True)
        try:
            os.startfile(exports)
        except Exception:
            pass
        return json.dumps({"success": True, "path": exports})

    def list_rules(self) -> str:
        return json.dumps(self.rule_engine.list_rules())

    def update_rule(self, rule_id: str, enabled: bool, weight: int) -> str:
        ok = self.rule_engine.set_override(rule_id, enabled, weight)
        return json.dumps({"success": bool(ok)})

    def mark_indicator_false_positive(self, evidence_id: str, rule_id: str, pid: int) -> str:
        conn = self.db._get_conn()
        conn.execute(
            "UPDATE risk_assessments SET is_false_positive = 1, analyst_override = "
            "'false_positive' WHERE evidence_id = ? AND rule_id = ? AND pid = ?",
            (evidence_id, rule_id, pid)
        )
        conn.commit()
        try:
            self.inv_engine.correlate_evidence(evidence_id)
        except Exception as e:
            logger.error(f"FP re-correlation failed: {e}")
        return json.dumps({"success": True})
