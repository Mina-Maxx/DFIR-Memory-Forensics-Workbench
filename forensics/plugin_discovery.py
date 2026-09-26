import os
import sys
import importlib
import pkgutil
from typing import Dict, List, Any
from core.logger import get_logger

logger = get_logger("plugin")

class PluginDiscovery:
    """Discovers installed Volatility 3 plugins categorized by OS and function."""

    DEFAULT_PLUGINS = {
        "windows": [
            {"name": "windows.info.Info", "category": "System", "description": "Memory image kernel build, architecture and symbols"},
            {"name": "windows.pslist.PsList", "category": "Process", "description": "Active process list from ActiveProcessLinks EPROCESS doubly-linked list"},
            {"name": "windows.psscan.PsScan", "category": "Process", "description": "Pool tag scan finding unlinked and terminated processes"},
            {"name": "windows.pstree.PsTree", "category": "Process", "description": "Process parent-child hierarchy tree"},
            {"name": "windows.cmdline.CmdLine", "category": "Process", "description": "Process command-line arguments from Process Environment Block"},
            {"name": "windows.netscan.NetScan", "category": "Network", "description": "TCP/UDP socket listeners, active connections, and owning PIDs"},
            {"name": "windows.netstat.NetStat", "category": "Network", "description": "Active network endpoints and socket state"},
            {"name": "windows.dlllist.DllList", "category": "Process", "description": "Loaded dynamic link libraries per process"},
            {"name": "windows.malfind.Malfind", "category": "Malware", "description": "Memory regions with PAGE_EXECUTE_READWRITE permissions and injected code"},
            {"name": "windows.handles.Handles", "category": "Handles", "description": "Open handles (files, registry keys, mutants, events)"},
            {"name": "windows.modules.Modules", "category": "Kernel", "description": "Loaded kernel drivers and system modules"},
            {"name": "windows.modscan.ModScan", "category": "Kernel", "description": "Scans memory for kernel drivers via pool tag carving"},
            {"name": "windows.registry.hivelist.HiveList", "category": "Registry", "description": "Locates registry hives in kernel memory"},
            {"name": "windows.registry.printkey.PrintKey", "category": "Registry", "description": "Reads registry keys, values and subkeys"},
            {"name": "windows.filescan.FileScan", "category": "Filesystem", "description": "Pool tag scan for FILE_OBJECT structures in memory"},
            {"name": "windows.dumpfiles.DumpFiles", "category": "Dumps", "description": "Extracts cached files, executables, and DLLs from memory"},
            {"name": "windows.memmap.Memmap", "category": "Dumps", "description": "Dumps virtual address space pages for a specific PID"},
            {"name": "windows.vadyarascan.VadYaraScan", "category": "YARA", "description": "Scans process memory with YARA rules"}
        ],
        "linux": [
            {"name": "linux.bash.Bash", "category": "Command", "description": "Recovers bash command history from memory"},
            {"name": "linux.pslist.PsList", "category": "Process", "description": "Enumerates Linux task_struct processes"},
            {"name": "linux.sockstat.Sockstat", "category": "Network", "description": "Active network sockets and listening ports"}
        ],
        "mac": [
            {"name": "mac.pslist.PsList", "category": "Process", "description": "Enumerates macOS processes"}
        ]
    }

    def __init__(self):
        self.cached_plugins: Dict[str, List[Dict[str, Any]]] = {}

    def discover_all(self) -> Dict[str, List[Dict[str, Any]]]:
        if self.cached_plugins:
            return self.cached_plugins

        plugins = {"windows": list(self.DEFAULT_PLUGINS["windows"]),
                   "linux": list(self.DEFAULT_PLUGINS["linux"]),
                   "mac": list(self.DEFAULT_PLUGINS["mac"])}

        # Try dynamic discovery if volatility3 is installed
        try:
            import volatility3.plugins
            for finder, name, ispkg in pkgutil.walk_packages(volatility3.plugins.__path__, volatility3.plugins.__name__ + "."):
                parts = name.split(".")
                if len(parts) >= 3:
                    os_type = parts[2].lower()
                    if os_type in ("windows", "linux", "mac"):
                        plugin_display = ".".join(parts[2:])
                        if not any(p["name"].startswith(plugin_display) for p in plugins.get(os_type, [])):
                            plugins.setdefault(os_type, []).append({
                                "name": plugin_display,
                                "category": "General",
                                "description": f"Volatility 3 {os_type} plugin"
                            })
        except Exception as exc:
            logger.debug(f"Dynamic plugin discovery skipped: {exc}")

        self.cached_plugins = plugins
        return self.cached_plugins

    def get_plugins_for_os(self, os_type: str) -> List[Dict[str, Any]]:
        all_p = self.discover_all()
        normalized = (os_type or "windows").lower()
        if "win" in normalized:
            return all_p.get("windows", [])
        elif "linux" in normalized:
            return all_p.get("linux", [])
        elif "mac" in normalized:
            return all_p.get("mac", [])
        return all_p.get("windows", [])
