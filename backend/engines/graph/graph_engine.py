"""
DFIR Workbench V2 - Graph Engine
Builds interactive SVG-compatible node-edge graphs linking processes, sockets,
memory anomalies, and YARA detections.
"""

from typing import Dict, List, Any
from backend.infrastructure.database.manager import DatabaseManager
from core.logger import get_logger

logger = get_logger("forensic")


def _is_external_ip(addr: str) -> bool:
    if not addr:
        return False
    try:
        import ipaddress
        ip = ipaddress.ip_address(str(addr).split("%")[0])
        return not (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_multicast or ip.is_reserved)
    except ValueError:
        return False


def _to_dict(obj):
    if obj is None:
        return {}
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if isinstance(obj, dict):
        return obj
    return vars(obj)


def build_graph(db: DatabaseManager, evidence_id: str) -> Dict[str, Any]:
    """Builds interactive node-edge graph with parent-child process relationships,

    observed network sockets, memory anomalies, and YARA matches.
    """
    procs = [_to_dict(p) for p in db.list_processes(evidence_id)]
    by_pid = {p.get("pid"): p for p in procs if p.get("pid") is not None}

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    seen = set()

    def add_node(nid: str, ntype: str, label: str, sub: str = "", risk: str = "Normal", pid: Any = None, extra: Any = None):
        if nid in seen:
            return
        seen.add(nid)
        n = {
            "id": nid, "type": ntype, "label": label or nid,
            "sub": sub or "", "risk": risk or "Normal"
        }
        if pid is not None:
            n["pid"] = pid
        if extra:
            n.update(extra)
        nodes.append(n)

    # 1. Add Process Nodes
    for p in procs:
        pid = p.get("pid")
        if pid is None:
            continue
        hidden = bool(p.get("in_psscan")) and not bool(p.get("in_pslist"))
        nid = f"proc:{p.get('id', pid)}"
        add_node(
            nid=nid,
            ntype="process",
            label=p.get("name") or f"PID {pid}",
            sub=f"PID {pid}" + (f" · score {p.get('risk_score')}" if p.get("risk_score") else ""),
            risk=p.get("risk_level") or "Normal",
            pid=pid,
            extra={
                "record_id": p.get("id"),
                "ppid": p.get("ppid"),
                "hidden": hidden,
                "cmdline": p.get("command_line") or "",
                "risk_score": p.get("risk_score", 0),
                "confidence": p.get("confidence", "Medium"),
                "severity": p.get("severity", "Normal"),
                "verdict": p.get("verdict", "unreviewed")
            }
        )

    def proc_node_id(pid):
        p = by_pid.get(pid)
        return f"proc:{p.get('id', pid)}" if p else None

    # 2. Add Process Parent-Child Hierarchy Edges (PPID -> PID)
    for p in procs:
        pid = p.get("pid")
        ppid = p.get("ppid")
        if pid and ppid and ppid in by_pid and ppid != pid:
            parent_nid = proc_node_id(ppid)
            child_nid = proc_node_id(pid)
            if parent_nid and child_nid:
                edges.append({
                    "source": parent_nid,
                    "target": child_nid,
                    "label": "spawns",
                    "type": "hierarchy"
                })

    # 3. Add Network Sockets and External IP Edges
    for c0 in db.list_connections(evidence_id):
        c = _to_dict(c0)
        addr = c.get("remote_addr") or ""
        if not addr or addr in ("0.0.0.0", "::", "127.0.0.1", "-", "*"):
            continue
        ext = _is_external_ip(addr)
        nid = f"ip:{addr}:{'ext' if ext else 'int'}"
        port = c.get("remote_port")
        ip_risk = "Medium" if ext else "Normal"
        add_node(nid, "ip", addr, f"{'Public Ext' if ext else 'Internal'} :{port or ''}", risk=ip_risk)
        src = proc_node_id(c.get("pid"))
        if src:
            edges.append({
                "source": src,
                "target": nid,
                "label": f"{c.get('protocol') or 'TCP'}:{port or ''}".strip(":"),
                "type": "network"
            })

    # 4. Add RWX Injected Memory Anomaly Nodes (Malfind)
    for m0 in db.list_memory_regions(evidence_id) if hasattr(db, "list_memory_regions") else []:
        m = _to_dict(m0)
        nid = f"mem:{m.get('id')}"
        add_node(nid, "mem", f"RWX {m.get('start_address') or ''}", m.get("protection") or "PAGE_EXECUTE_READWRITE", risk="Critical")
        src = proc_node_id(m.get("pid"))
        if src:
            edges.append({
                "source": src,
                "target": nid,
                "label": "injected",
                "type": "memory"
            })

    # 5. Add YARA Match Nodes
    for y in db.list_yara_matches(evidence_id):
        nid = f"yara:{y['id']}"
        add_node(nid, "yara", f"YARA: {y['rule']}", f"PID {y.get('pid', '')} {y.get('offset', '')}", risk="Critical")
        src = proc_node_id(y.get("pid"))
        if src:
            edges.append({
                "source": src,
                "target": nid,
                "label": "yara",
                "type": "malware"
            })

    # Keep all processes or connected nodes
    connected = {e["source"] for e in edges} | {e["target"] for e in edges}
    nodes = [n for n in nodes if n["type"] == "process" or n["id"] in connected]

    logger.info(f"Graph built for evidence {evidence_id}: {len(nodes)} nodes, {len(edges)} edges")
    return {
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "processes": sum(1 for n in nodes if n["type"] == "process"),
            "ips": sum(1 for n in nodes if n["type"] == "ip"),
            "dlls": sum(1 for n in nodes if n["type"] == "dll"),
            "memory": sum(1 for n in nodes if n["type"] == "mem"),
            "yara": sum(1 for n in nodes if n["type"] == "yara")
        }
    }
