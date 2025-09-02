"""
Core module for the Advanced Agentic Exploit Discovery System (AAEDS)

This module provides the foundational components for autonomous exploit discovery
through reasoning, planning, execution, and validation.
"""

from .engine import ExploitDiscoveryEngine
from .reasoning import ReasoningEngine
from .planning import PlanningEngine
from .execution import ExecutionEngine
from .validation import ValidationEngine
from .analyzer import ProtocolAnalyzer, CodebaseAnalyzer

__all__ = [
    'ExploitDiscoveryEngine',
    'ReasoningEngine',
    'PlanningEngine',
    'ExecutionEngine',
    'ValidationEngine',
    'ProtocolAnalyzer',
    'CodebaseAnalyzer'
]

__version__ = '2.0.0'