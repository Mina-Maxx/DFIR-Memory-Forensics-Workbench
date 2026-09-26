"""
Database Access Layer - Backward Compatibility Facade
Re-exports DatabaseManager from backend.infrastructure.database.manager
"""

from backend.infrastructure.database.manager import DatabaseManager

__all__ = ["DatabaseManager"]
