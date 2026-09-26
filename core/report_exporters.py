import os
import json
import csv
from datetime import datetime
from typing import List, Dict, Any
from core.database import DatabaseManager
from core.logger import get_logger

logger = get_logger("app")

def _to_dict(obj):
    if obj is None:
        return {}
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if isinstance(obj, dict):
        return obj
    return vars(obj)

def _sanitize_csv_cell(val: Any) -> str:
    s = str(val if val is not None else "")
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + s
    return s

def build_stix(iocs: list) -> str:
    """Builds valid STIX 2.1 JSON bundle from IOC objects."""
    objects = [{
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--vol3-dfir-workbench-001",
        "name": "Vol3 DFIR Workbench",
        "identity_class": "system"
    }]
    now = datetime.now().isoformat(timespec="seconds")
    for ioc in iocs:
        d = _to_dict(ioc)
        t = (d.get("type") or "").lower()
        v = str(d.get("value") or "").replace("'", "")
        if not v:
            continue

        pattern = None
        if t in ("ip", "ipv4"):
            pattern = f"[ipv4-addr:value = '{v}']"
        elif t in ("domain", "fqdn"):
            pattern = f"[domain-name:value = '{v}']"
        elif t in ("sha256", "hash"):
            pattern = f"[file:hashes.'SHA-256' = '{v}']"
        elif t == "md5":
            pattern = f"[file:hashes.'MD5' = '{v}']"
        elif t == "process":
            pattern = f"[process:name = '{v}']"

        if pattern:
            import uuid
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": now,
                "modified": now,
                "name": f"{t.upper()} IOC: {v}",
                "description": d.get("description") or "",
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": now
            })

    import uuid
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects
    }
    return json.dumps(bundle, indent=2, ensure_ascii=False)

def export_package(db: DatabaseManager, case_id: str, report_engine, workspace_path: str) -> str:
    """Exports full investigation package with HTML report, JSONs, and sanitized CSVs."""
    case = db.get_case(case_id)
    if not case:
        raise ValueError(f"Case {case_id} not found")

    out = os.path.join(case.workspace_path, "exports", f"package_{case_id}")
    os.makedirs(out, exist_ok=True)

    # 1. HTML report
    html_content = report_engine.generate_html_report(case_id)
    with open(os.path.join(out, f"report_{case_id}.html"), "w", encoding="utf-8") as fh:
        fh.write(html_content)

    # 2. IOCs JSON and STIX
    iocs = [_to_dict(i) for i in db.list_iocs(case_id)]
    with open(os.path.join(out, "iocs.json"), "w", encoding="utf-8") as fh:
        json.dump(iocs, fh, indent=2, ensure_ascii=False, default=str)

    with open(os.path.join(out, "iocs.stix.json"), "w", encoding="utf-8") as fh:
        fh.write(build_stix(iocs))

    # 3. Findings JSON
    findings = [_to_dict(f) for f in db.list_findings(case_id)]
    with open(os.path.join(out, "findings.json"), "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2, ensure_ascii=False, default=str)

    # 4. Command history CSV (sanitized against CSV injection)
    execs = [_to_dict(x) for x in db.list_executions() if getattr(x, "case_id", "") == case_id]
    with open(os.path.join(out, "command_history.csv"), "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["start", "end", "plugin", "args", "status", "rows", "command"])
        for x in execs:
            writer.writerow([
                _sanitize_csv_cell(x.get("start_time")),
                _sanitize_csv_cell(x.get("end_time")),
                _sanitize_csv_cell(x.get("plugin_name")),
                _sanitize_csv_cell(x.get("arguments")),
                _sanitize_csv_cell(x.get("status")),
                x.get("result_count") or 0,
                _sanitize_csv_cell(x.get("command"))
            ])

    # 5. Timeline CSV (sanitized against CSV injection)
    events = [_to_dict(e) for e in db.list_events() if e.case_id == case_id]
    with open(os.path.join(out, "timeline.csv"), "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["timestamp", "event_type", "pid", "process_name", "description", "severity"])
        for e in events:
            writer.writerow([
                _sanitize_csv_cell(e.get("timestamp")),
                _sanitize_csv_cell(e.get("event_type")),
                e.get("pid") or "",
                _sanitize_csv_cell(e.get("process_name")),
                _sanitize_csv_cell(e.get("description")),
                _sanitize_csv_cell(e.get("severity"))
            ])

    logger.info(f"Investigation package exported: {out}")
    return out
