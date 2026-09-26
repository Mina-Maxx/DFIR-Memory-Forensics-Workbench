import time
import json
import threading
from typing import Dict, List, Optional, Callable, Any
from core.models import PluginExecution, PluginResult
from core.database import DatabaseManager
from forensics.vol_adapter import VolAdapter
from forensics.result_parser import ResultParser
from core.logger import get_logger

logger = get_logger("plugin")

class JobManager:
    """Pure-Python Threaded Job Manager for asynchronous Volatility 3 execution."""

    TRIAGE_PLUGINS = [
        "windows.info.Info",
        "windows.pslist.PsList",
        "windows.psscan.PsScan",
        "windows.pstree.PsTree",
        "windows.cmdline.CmdLine",
        "windows.netscan.NetScan",
        "windows.malfind.Malfind"
    ]

    def __init__(self, db: DatabaseManager, vol_adapter: VolAdapter):
        self.db = db
        self.vol_adapter = vol_adapter
        self.parser = ResultParser()
        self._active_threads: Dict[str, threading.Thread] = {}
        self._cancellation_flags: Dict[str, bool] = {}
        self._listeners: List[Callable[[str, Dict[str, Any]], None]] = []
        self._triage_queue: Dict[str, List[str]] = {} # evidence_id -> [plugin_names]
        self._lock = threading.RLock()

    def subscribe(self, callback: Callable[[str, Dict[str, Any]], None]):
        """Subscribe to job events: (event_name, data)."""
        with self._lock:
            self._listeners.append(callback)

    def _broadcast(self, event: str, data: Dict[str, Any]):
        with self._lock:
            callbacks = list(self._listeners)
        for cb in callbacks:
            try:
                cb(event, data)
            except Exception as e:
                logger.debug(f"Event broadcast error: {e}")

    def run_plugin(self, evidence_id: str, plugin_name: str, extra_args: Optional[List[str]] = None) -> PluginExecution:
        evidence = self.db.get_evidence(evidence_id)
        if not evidence:
            raise ValueError(f"Evidence {evidence_id} not found.")

        args_str = json.dumps(extra_args or [])
        execution = PluginExecution(
            evidence_id=evidence_id,
            case_id=evidence.case_id,
            plugin_name=plugin_name,
            arguments=args_str,
            command="",
            status="Running",
            current_activity=f"Launching {plugin_name}..."
        )
        self.db.create_execution(execution)

        exec_id = execution.id
        self._cancellation_flags[exec_id] = False

        self._broadcast("job_started", {
            "execution_id": exec_id,
            "evidence_id": evidence_id,
            "plugin_name": plugin_name
        })

        t = threading.Thread(
            target=self._worker_run,
            args=(exec_id, evidence.filepath, plugin_name, extra_args or []),
            daemon=True
        )
        with self._lock:
            self._active_threads[exec_id] = t
        t.start()
        return execution

    def _worker_run(self, exec_id: str, evidence_path: str, plugin_name: str, args: List[str]):
        start_time = time.time()
        logger.info(f"Worker started for {plugin_name} (Job: {exec_id})")

        def on_output(line: str):
            self.db.update_execution_activity(exec_id, f"Running: {line[:120]}", stdout_tail=line)
            self._broadcast("job_activity", {
                "execution_id": exec_id,
                "activity": line[:150],
                "line": line
            })

        def is_cancelled() -> bool:
            return self._cancellation_flags.get(exec_id, False)

        try:
            res = self.vol_adapter.execute_plugin(
                evidence_path,
                plugin_name,
                extra_args=args,
                on_output_callback=on_output,
                is_cancelled_callback=is_cancelled
            )

            runtime = round(time.time() - start_time, 2)
            stdout = res.get("stdout", "")
            stderr = res.get("stderr", "")
            status = res.get("status", "Failed")

            headers, rows = self.parser.parse_json_output(stdout)

            # Save execution update
            self.db.update_execution_status(
                exec_id,
                status=status,
                error_message=stderr if status != "Completed" else "",
                runtime_seconds=runtime,
                result_count=len(rows)
            )

            # Store result
            ex_obj = self.db.get_execution(exec_id)
            if ex_obj:
                pr = PluginResult(
                    execution_id=exec_id,
                    evidence_id=ex_obj.evidence_id,
                    plugin_name=plugin_name,
                    headers=json.dumps(headers),
                    data=json.dumps(rows[:5000]) if len(rows) > 5000 else json.dumps(rows),
                    row_count=len(rows)
                )
                self.db.store_result(pr, raw_data=rows if len(rows) > 5000 else None)

            self._broadcast("job_finished", {
                "execution_id": exec_id,
                "evidence_id": ex_obj.evidence_id if ex_obj else "",
                "plugin_name": plugin_name,
                "status": status,
                "result_count": len(rows),
                "runtime_seconds": runtime,
                "error": stderr if status != "Completed" else ""
            })

            # Check triage queue continuation
            if ex_obj:
                self._check_triage_next(ex_obj.evidence_id)

        except Exception as e:
            runtime = round(time.time() - start_time, 2)
            logger.error(f"Plugin execution failed for {plugin_name}: {e}")
            self.db.update_execution_status(exec_id, status="Failed", error_message=str(e), runtime_seconds=runtime)
            self._broadcast("job_finished", {
                "execution_id": exec_id,
                "evidence_id": "",
                "plugin_name": plugin_name,
                "status": "Failed",
                "error": str(e)
            })
        finally:
            with self._lock:
                self._active_threads.pop(exec_id, None)
                self._cancellation_flags.pop(exec_id, None)

    def cancel_job(self, execution_id: str) -> bool:
        with self._lock:
            if execution_id in self._cancellation_flags:
                self._cancellation_flags[execution_id] = True
                logger.info(f"Cancellation requested for job {execution_id}")
                return True
        return False

    def start_automated_triage(self, evidence_id: str) -> List[str]:
        """Queues full forensic triage plugins sequentially."""
        plugins_to_run = list(self.TRIAGE_PLUGINS)
        with self._lock:
            self._triage_queue[evidence_id] = list(plugins_to_run[1:]) # remaining

        first_plugin = plugins_to_run[0]
        self.run_plugin(evidence_id, first_plugin)
        return plugins_to_run

    def _check_triage_next(self, evidence_id: str):
        completed = False
        next_plugin = None
        with self._lock:
            queue = self._triage_queue.get(evidence_id, [])
            if not queue:
                self._triage_queue.pop(evidence_id, None)
                completed = True
            else:
                next_plugin = queue.pop(0)

        if completed:
            self._broadcast("triage_completed", {"evidence_id": evidence_id})
            return

        if next_plugin:
            logger.info(f"Triage continuing: next plugin is {next_plugin}")
            self.run_plugin(evidence_id, next_plugin)
