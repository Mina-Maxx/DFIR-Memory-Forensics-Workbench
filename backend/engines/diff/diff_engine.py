"""
DFIR Workbench V2 - Memory Snapshot Diff Engine
Computes delta states between memory dumps: processes, sockets, risk delta.
"""

from typing import Dict, Any, List
from backend.infrastructure.database.manager import DatabaseManager
from core.logger import get_logger

logger = get_logger("forensic")


def _to_dict(obj):
    if obj is None:
        return {}
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if isinstance(obj, dict):
        return obj
    return vars(obj)


def _net_key(c: Dict) -> str:
    return f"{c.get('protocol')}:{c.get('local_addr')}:{c.get('local_port')}->{c.get('remote_addr')}:{c.get('remote_port')}"


def diff_evidence(db: DatabaseManager, ev_a: str, ev_b: str) -> Dict[str, Any]:
    pa = [_to_dict(p) for p in db.list_processes(ev_a)]
    pb = [_to_dict(p) for p in db.list_processes(ev_b)]

    def pkey(p):
        return (p.get("pid"), (p.get("name") or "").lower())

    ka = {pkey(p): p for p in pa}
    kb = {pkey(p): p for p in pb}

    LIMIT = 200
    added = [p for k, p in kb.items() if k not in ka][:LIMIT]
    removed = [p for k, p in ka.items() if k not in kb][:LIMIT]

    changed = []
    for k, b in kb.items():
        if k not in ka:
            continue
        a = ka[k]
        fields = {}
        for f in ("ppid", "command_line", "create_time", "exit_time", "risk_level"):
            if (a.get(f) or "") != (b.get(f) or ""):
                fields[f] = {"a": a.get(f), "b": b.get(f)}
        if fields:
            changed.append({"pid": b.get("pid"), "name": b.get("name"), "changes": fields})
    changed = changed[:LIMIT]

    na = [_to_dict(c) for c in db.list_connections(ev_a)]
    nb = [_to_dict(c) for c in db.list_connections(ev_b)]
    sa = {_net_key(c) for c in na}
    sb = {_net_key(c) for c in nb}
    net_added = [c for c in nb if _net_key(c) not in sa][:LIMIT]
    net_removed = [c for c in na if _net_key(c) not in sb][:LIMIT]

    # Delta risk calculations
    wa_map = {p.get("pid"): p.get("risk_score", 0) for p in pa}
    wb_map = {p.get("pid"): p.get("risk_score", 0) for p in pb}

    indicator_changes = []
    for k, b in kb.items():
        a = ka.get(k)
        if not a:
            continue
        sa_score = wa_map.get(b.get("pid"), 0)
        sb_score = wb_map.get(b.get("pid"), 0)
        if sa_score != sb_score:
            indicator_changes.append({
                "pid": b.get("pid"),
                "name": b.get("name"),
                "score_a": sa_score,
                "score_b": sb_score,
                "delta": sb_score - sa_score
            })

    return {
        "processes_added": added,
        "processes_removed": removed,
        "processes_changed": changed,
        "network_added": net_added,
        "network_removed": net_removed,
        "indicator_changes": indicator_changes,
        "summary": {
            "proc_a_count": len(pa),
            "proc_b_count": len(pb),
            "net_a_count": len(na),
            "net_b_count": len(nb)
        }
    }
