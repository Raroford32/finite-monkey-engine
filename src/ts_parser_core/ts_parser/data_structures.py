#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Data structure definitions used by the multi-language analyzer.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum


class LanguageType(Enum):
    """Supported programming languages."""
    SOLIDITY = "solidity"
    RUST = "rust"
    CPP = "cpp"
    MOVE = "move"
    GO = "go"


class CallType(Enum):
    """Types of call relationships."""
    DIRECT = "direct"              # Direct function call
    VIRTUAL = "virtual"            # Virtual function call (C++)
    ASYNC = "async"                # Asynchronous call (Rust)
    EXTERNAL = "external"          # External contract call (Solidity)
    ENTRY = "entry"                # Entry function call (Move)
    TRAIT = "trait"                # Trait method call (Rust)
    MACRO = "macro"                # Macro invocation (Rust)
    CONSTRUCTOR = "constructor"    # Constructor invocation
    MODIFIER = "modifier"          # Modifier invocation (Solidity)


@dataclass
class FunctionInfo:
    """Enhanced function information."""
    name: str
    full_name: str
    language: LanguageType
    
    # Common attributes
    visibility: str = "private"
    parameters: List[str] = field(default_factory=list)
    return_type: Optional[str] = None
    calls: List[str] = field(default_factory=list)
    line_number: int = 0
    
    # Language-specific attributes
    is_async: bool = False          # Rust
    is_unsafe: bool = False         # Rust
    is_virtual: bool = False        # C++
    is_pure_virtual: bool = False   # C++
    is_override: bool = False       # C++
    is_entry: bool = False          # Move
    is_native: bool = False         # Move
    is_payable: bool = False        # Solidity
    is_view: bool = False           # Solidity
    is_pure: bool = False           # Solidity
    
    # Advanced attributes
    modifiers: List[str] = field(default_factory=list)      # Solidity modifiers
    acquires: List[str] = field(default_factory=list)       # Move acquires
    generic_params: List[str] = field(default_factory=list) # Generic parameters
    
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StructInfo:
    """Enhanced structure/class information."""
    name: str
    full_name: str
    language: LanguageType
    
    # Common attributes
    fields: List[str] = field(default_factory=list)
    methods: List[str] = field(default_factory=list)
    line_number: int = 0
    
    # Language-specific attributes
    base_classes: List[str] = field(default_factory=list)   # C++ base classes
    abilities: List[str] = field(default_factory=list)      # Move abilities
    is_interface: bool = False                              # Solidity interface
    is_abstract: bool = False                               # C++ abstract class
    is_template: bool = False                               # C++ template
    derives: List[str] = field(default_factory=list)        # Rust derives
    
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ModuleInfo:
    """Enhanced module information."""
    name: str
    full_name: str
    language: LanguageType
    
    # Contents
    functions: List[FunctionInfo] = field(default_factory=list)
    structs: List[StructInfo] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    line_number: int = 0
    
    # Language-specific attributes
    inheritance: List[str] = field(default_factory=list)    # Solidity contracts
    address: Optional[str] = None                           # Move modules
    is_library: bool = False                                # Solidity
    namespace_type: Optional[str] = None                    # C++ namespaces
    
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CallGraphEdge:
    """Call-graph edge information."""
    caller: str
    callee: str
    call_type: CallType = CallType.DIRECT
    language: Optional[LanguageType] = None
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisStats:
    """分析统计信息"""
    language: LanguageType
    modules_count: int = 0
    functions_count: int = 0
    structs_count: int = 0
    call_relationships: int = 0
    language_specific_features: Dict[str, int] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'language': self.language.value,
            'modules_count': self.modules_count,
            'functions_count': self.functions_count,
            'structs_count': self.structs_count,
            'call_relationships': self.call_relationships,
            'language_specific_features': self.language_specific_features
        } 
