import json
from typing import Tuple, List, Dict, Any

class ResultParser:
    """Parses Volatility 3 output into structured column headers and tabular data rows."""

    def parse_json_output(self, stdout: str) -> Tuple[List[str], List[List[str]]]:
        if not stdout or not stdout.strip():
            return [], []

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            # Volatility 3 may output framework warnings or banners before the JSON array
            clean = stdout.strip()
            b_idx = clean.find("[")
            c_idx = clean.find("{")
            start = -1
            if b_idx != -1 and c_idx != -1:
                start = min(b_idx, c_idx)
            elif b_idx != -1:
                start = b_idx
            elif c_idx != -1:
                start = c_idx

            if start > 0:
                try:
                    data = json.loads(clean[start:])
                except json.JSONDecodeError:
                    return ["Raw Output"], [[line] for line in stdout.splitlines()]
            else:
                return ["Raw Output"], [[line] for line in stdout.splitlines()]

        if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
            headers = [k for k in data[0].keys() if not k.startswith("__")]
            rows = []
            for item in data:
                row = []
                for h in headers:
                    val = item.get(h)
                    if val is None:
                        row.append("N/A")
                    elif isinstance(val, (dict, list)):
                        row.append(json.dumps(val))
                    else:
                        row.append(str(val))
                rows.append(row)
            return headers, rows

        elif isinstance(data, dict):
            if "columns" in data and "data" in data:
                return data["columns"], [[str(i) for i in row] for row in data["data"]]
            else:
                headers = [k for k in data.keys() if not k.startswith("__")]
                row = [str(data.get(h, "N/A")) for h in headers]
                return headers, [row]

        elif isinstance(data, list) and len(data) > 0 and isinstance(data[0], list):
            headers = [f"Col {i}" for i in range(len(data[0]))]
            return headers, [[str(i) for i in row] for row in data]

        return ["Raw Output"], [[json.dumps(data)]]
