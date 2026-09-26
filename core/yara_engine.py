"""
YARA Engine Backward Compatibility Facade
Re-exports YaraEngine from backend.engines.yara
"""

from backend.engines.yara import YaraEngine, available, validate_rule_file

__all__ = ["YaraEngine", "available", "validate_rule_file"]
