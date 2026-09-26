"""
IOC Engine Backward Compatibility Facade
Re-exports IOCEngine from backend.engines.ioc
"""

from backend.engines.ioc import IOCEngine

__all__ = ["IOCEngine"]
