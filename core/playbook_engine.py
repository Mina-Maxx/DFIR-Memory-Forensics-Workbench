import os
import yaml
import threading
from typing import List, Dict, Any, Optional, Callable
from core.job_manager import JobManager
from core.investigation_engine import InvestigationEngine
from core.risk_engine import RiskEngine
from core.logger import get_logger

logger = get_logger("app")

class PlaybookEngine:
    """Loads and executes multi-step investigation playbooks."""

    def __init__(self, job_manager: JobManager, playbooks_file: Optional[str] = None):
        self.job_mgr = job_manager
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.playbooks_file = playbooks_file or os.path.join(base_dir, "data", "playbooks.yaml")
        self.playbooks: List[Dict[str, Any]] = self._load()
        self._running = False
        self._queue: List[str] = []
        self._active_playbook: Optional[Dict[str, Any]] = None
        self._evidence_id: str = ""
        self._listeners: List[Callable[[str], None]] = []

    def _load(self) -> List[Dict[str, Any]]:
        if not os.path.isfile(self.playbooks_file):
            return []
        try:
            with open(self.playbooks_file, encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
                return data.get("playbooks", [])
        except Exception as exc:
            logger.error(f"Failed loading playbooks: {exc}")
            return []

    def subscribe(self, callback: Callable[[str], None]):
        self._listeners.append(callback)

    def _emit(self, msg: str):
        for cb in self._listeners:
            try:
                cb(msg)
            except Exception:
                pass

    def _extract_plugins(self, p: Dict[str, Any]) -> List[str]:
        plugins = []
        if "plugins" in p and isinstance(p["plugins"], list):
            for pl in p["plugins"]:
                if isinstance(pl, str):
                    normalized = "windows.malfind.Malfind" if "malfind" in pl.lower() else pl
                    plugins.append(normalized)
        elif "steps" in p and isinstance(p["steps"], list):
            for s in p["steps"]:
                if isinstance(s, dict) and s.get("plugin"):
                    pl = s.get("plugin")
                    normalized = "windows.malfind.Malfind" if "malfind" in pl.lower() else pl
                    plugins.append(normalized)
                elif isinstance(s, str):
                    normalized = "windows.malfind.Malfind" if "malfind" in s.lower() else s
                    plugins.append(normalized)
        return plugins

    def list_playbooks(self) -> List[Dict[str, Any]]:
        return [{
            "id": p.get("id"),
            "name": p.get("name"),
            "description": p.get("description", ""),
            "author": p.get("author", "DFIR-Workbench"),
            "steps": len(self._extract_plugins(p)),
            "plugins": self._extract_plugins(p)
        } for p in self.playbooks]

    def run_playbook(self, playbook_id: str, evidence_id: str) -> bool:
        if self._running:
            return False

        pb = next((p for p in self.playbooks if p.get("id") == playbook_id), None)
        if not pb:
            return False

        self._active_playbook = pb
        self._evidence_id = evidence_id
        self._running = True
        self._queue = self._extract_plugins(pb)

        self._emit(f"Starting playbook '{pb.get('name')}' ({len(self._queue)} steps)...")

        # Run in separate thread
        threading.Thread(target=self._execute_steps, daemon=True).start()
        return True

    def _execute_steps(self):
        try:
            for i, plugin in enumerate(self._queue, 1):
                self._emit(f"Step {i}/{len(self._queue)}: Running {plugin}...")
                ex = self.job_mgr.run_plugin(self._evidence_id, plugin)
                # Wait for job to finish with timeout protection
                import time
                wait_start = time.time()
                while time.time() - wait_start < 600:
                    time.sleep(1)
                    curr = self.job_mgr.db.get_execution(ex.id)
                    if curr and curr.status in ("Completed", "Failed", "Cancelled"):
                        break

            # Finish: trigger re-correlation
            self._emit("Refreshing cross-plugin correlation and risk scoring...")
            inv = InvestigationEngine(self.job_mgr.db, RiskEngine())
            inv.correlate_evidence(self._evidence_id)
            self._emit(f"Playbook '{self._active_playbook.get('name')}' completed successfully!")
        except Exception as e:
            logger.error(f"Playbook execution failed: {e}")
            self._emit(f"Playbook error: {e}")
        finally:
            self._running = False
            self._active_playbook = None

    @property
    def is_running(self) -> bool:
        return self._running
