import subprocess
import os
import sys
import shutil
import uuid
from typing import List, Dict, Any, Optional, Callable
from core.logger import get_logger

logger = get_logger("forensic")

class VolAdapter:
    """Manages Volatility 3 CLI subprocess execution with progress, cancel and timeout handling."""

    def __init__(self, workspace_path: str):
        self.workspace_path = os.path.abspath(workspace_path)
        self.tmp_dir = os.path.join(self.workspace_path, ".run_tmp")
        self.dumps_dir = os.path.join(self.workspace_path, "dumps")
        os.makedirs(self.tmp_dir, exist_ok=True)
        os.makedirs(self.dumps_dir, exist_ok=True)
        self.vol_prefix = self._find_vol_prefix()

    def _find_vol_prefix(self) -> List[str]:
        # 1. Check if running inside PyInstaller bundle
        if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
            bundled_vol = os.path.join(sys._MEIPASS, "volatility3_src")
            if os.path.isdir(bundled_vol):
                return [sys.executable, "--vol-worker"]

        # 2. Check system PATH
        vol_path = (shutil.which("vol") or shutil.which("vol.py") or
                    shutil.which("volatility") or shutil.which("vol3") or
                    shutil.which("volatility3"))
        if vol_path:
            return [vol_path]

        # 3. Check Python bin / scripts folder (cross-platform for Windows & Linux)
        py_dir = os.path.dirname(sys.executable)
        for candidate_name in ("vol", "vol.py", "vol3", "volatility", "vol.exe"):
            for sub in ("bin", "Scripts", ""):
                candidate_path = os.path.join(py_dir, sub, candidate_name) if sub else os.path.join(py_dir, candidate_name)
                if os.path.isfile(candidate_path):
                    return [candidate_path]

        # 4. Check if vol.py exists relative to imported volatility3 package
        try:
            import volatility3
            pkg_dir = os.path.dirname(os.path.abspath(volatility3.__file__))
            candidate_vol = os.path.join(os.path.dirname(pkg_dir), "vol.py")
            if os.path.isfile(candidate_vol):
                return [sys.executable, candidate_vol]
        except Exception:
            pass

        # 5. Fallback: Standalone runner script in workspace
        runner_path = os.path.join(self.workspace_path, "vol_runner.py")
        if not os.path.isfile(runner_path):
            with open(runner_path, "w", encoding="utf-8") as f:
                f.write(
                    'import sys\n'
                    'import volatility3.cli\n'
                    'if __name__ == "__main__":\n'
                    '    sys.stderr.reconfigure(encoding="utf-8")\n'
                    '    sys.stdout.reconfigure(encoding="utf-8")\n'
                    '    volatility3.cli.main()\n'
                )
        return [sys.executable, runner_path]

    def execute_plugin(self, evidence_path: str, plugin_name: str,
                       extra_args: Optional[List[str]] = None,
                       output_dir: Optional[str] = None,
                       on_output_callback: Optional[Callable[[str], None]] = None,
                       is_cancelled_callback: Optional[Callable[[], bool]] = None,
                       timeout_seconds: int = 1800) -> Dict[str, Any]:
        """
        Executes a Volatility 3 plugin.
        Strictly prevents arbitrary command injection and output redirection flags.
        """
        if not os.path.isfile(evidence_path):
            raise FileNotFoundError(f"Evidence file not found: {evidence_path}")

        args = extra_args or []
        FORBIDDEN_FLAGS = {"-o", "--output-dir", "--output-file", "-w", "--write-file", "--dump-dir"}
        safe_args = []
        skip_next = False
        for arg in args:
            if skip_next:
                skip_next = False
                continue
            if arg in FORBIDDEN_FLAGS:
                skip_next = True
                continue
            if any(arg.startswith(f"{ff}=") for ff in FORBIDDEN_FLAGS):
                continue
            safe_args.append(arg)

        target_dumps = output_dir if output_dir else self.dumps_dir
        safe_output = os.path.abspath(target_dumps)
        os.makedirs(safe_output, exist_ok=True)

        cmd = list(self.vol_prefix) + ["-f", os.path.abspath(evidence_path), "-o", safe_output, "--renderer", "json", plugin_name] + safe_args
        cmd_str = " ".join(f'"{c}"' if " " in c else c for c in cmd)
        logger.info(f"Executing Volatility: {cmd_str}")

        creationflags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        run_id = uuid.uuid4().hex[:8]
        stdout_file_path = os.path.join(self.tmp_dir, f"out_{run_id}.log")
        stderr_file_path = os.path.join(self.tmp_dir, f"err_{run_id}.log")

        try:
            with open(stdout_file_path, "wb") as out_f, open(stderr_file_path, "wb") as err_f:
                proc = subprocess.Popen(
                    cmd,
                    stdout=out_f,
                    stderr=err_f,
                    creationflags=creationflags
                )

                import time
                start_t = time.time()
                while proc.poll() is None:
                    if is_cancelled_callback and is_cancelled_callback():
                        proc.kill()
                        logger.warning(f"Plugin {plugin_name} cancelled by user.")
                        return {
                            "command": cmd_str, "exit_code": -1, "stdout": "",
                            "stderr": "Cancelled by user.", "status": "Cancelled"
                        }

                    if time.time() - start_t > timeout_seconds:
                        proc.kill()
                        logger.error(f"Plugin {plugin_name} timed out after {timeout_seconds}s.")
                        return {
                            "command": cmd_str, "exit_code": -2, "stdout": "",
                            "stderr": f"Execution timed out ({timeout_seconds}s).", "status": "Failed"
                        }

                    # Poll stdout for live progress
                    if on_output_callback and os.path.isfile(stdout_file_path):
                        try:
                            with open(stdout_file_path, "r", encoding="utf-8", errors="replace") as r_f:
                                lines = r_f.readlines()
                                if lines:
                                    on_output_callback(lines[-1].strip())
                        except Exception:
                            pass
                    time.sleep(0.5)

                proc.wait()

            with open(stdout_file_path, "r", encoding="utf-8", errors="replace") as out_f:
                stdout_content = out_f.read()
            with open(stderr_file_path, "r", encoding="utf-8", errors="replace") as err_f:
                stderr_content = err_f.read()

            status = "Completed" if proc.returncode == 0 else "Failed"
            return {
                "command": cmd_str,
                "exit_code": proc.returncode,
                "stdout": stdout_content,
                "stderr": stderr_content,
                "status": status
            }

        finally:
            for f in (stdout_file_path, stderr_file_path):
                if os.path.isfile(f):
                    try:
                        os.remove(f)
                    except OSError:
                        pass
