#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tree-sitter multi-language code analyzer package.
Supports AST parsing and call-graph analysis for Solidity, Rust, C++, and Move.
"""

from .ts_parser import *

print("✅ Tree-sitter parsers loaded, supporting four languages")

__all__ = [
    'LanguageType', 'CallType',
    'FunctionInfo', 'StructInfo', 'ModuleInfo', 'CallGraphEdge',
    'LanguageConfig', 'get_language_config',
    'MultiLanguageAnalyzer'
] 
