"""
DFIR Workbench V2 - API Context
Provides safe access to the bridge instance without circular imports.
"""

from typing import Optional, Any

_bridge = None


def set_bridge(bridge_instance: Any):
    global _bridge
    _bridge = bridge_instance


def get_bridge() -> Any:
    global _bridge
    if _bridge is None:
        try:
            from flask import current_app
            if current_app and "BRIDGE" in current_app.config:
                return current_app.config["BRIDGE"]
        except Exception:
            pass
    return _bridge
