"""
Graph Builder Backward Compatibility Facade
Re-exports build_graph from backend.engines.graph
"""

from backend.engines.graph import build_graph

__all__ = ["build_graph"]
