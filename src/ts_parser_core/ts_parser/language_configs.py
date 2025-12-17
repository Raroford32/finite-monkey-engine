#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Language configuration module.
Defines parser configuration and language-specific rules.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set
from .data_structures import LanguageType


@dataclass
class LanguageConfig:
    """Language configuration."""
    language: LanguageType
    file_extensions: List[str]
    separator: str  # Namespace separator
    
    # AST node type configuration
    module_types: List[str]
    function_types: List[str]
    struct_types: List[str]
    class_types: List[str] = field(default_factory=list)
    interface_types: List[str] = field(default_factory=list)
    enum_types: List[str] = field(default_factory=list)
    
    # Visibility keywords
    visibility_keywords: Set[str] = field(default_factory=set)
    
    # Language-specific keywords
    special_keywords: Set[str] = field(default_factory=set)
    
    # Call-expression node types
    call_expression_types: List[str] = field(default_factory=list)
    
    # Comment tokens
    line_comment: str = "//"
    block_comment_start: str = "/*"
    block_comment_end: str = "*/"


# Solidity configuration
SOLIDITY_CONFIG = LanguageConfig(
    language=LanguageType.SOLIDITY,
    file_extensions=['.sol'],
    separator='.',
    module_types=['contract_declaration', 'library_declaration', 'interface_declaration'],
    function_types=['function_definition', 'constructor_definition', 'modifier_definition'],
    struct_types=['struct_definition'],
    class_types=['contract_declaration'],
    interface_types=['interface_declaration'],
    enum_types=['enum_definition'],
    visibility_keywords={'public', 'private', 'internal', 'external'},
    special_keywords={'payable', 'view', 'pure', 'override', 'virtual', 'constant'},
    call_expression_types=['call_expression'],
    line_comment='//',
    block_comment_start='/*',
    block_comment_end='*/'
)


# Rust configuration
RUST_CONFIG = LanguageConfig(
    language=LanguageType.RUST,
    file_extensions=['.rs'],
    separator='::',
    module_types=['mod_item'],
    function_types=['function_item'],
    struct_types=['struct_item'],
    class_types=[],  # Rust has no classes
    interface_types=['trait_item'],
    enum_types=['enum_item'],
    visibility_keywords={'pub', 'crate'},
    special_keywords={'async', 'unsafe', 'const', 'static', 'extern', 'fn', 'impl'},
    call_expression_types=['call_expression', 'method_call_expression', 'macro_invocation'],
    line_comment='//',
    block_comment_start='/*',
    block_comment_end='*/'
)


# C++ configuration
CPP_CONFIG = LanguageConfig(
    language=LanguageType.CPP,
    file_extensions=['.cpp', '.cc', '.cxx', '.h', '.hpp', '.hxx'],
    separator='::',
    module_types=['namespace_definition'],
    function_types=['function_definition', 'function_declarator'],
    struct_types=['struct_specifier', 'class_specifier'],
    class_types=['class_specifier'],
    interface_types=[],  # C++ has no dedicated interfaces
    enum_types=['enum_specifier'],
    visibility_keywords={'public', 'private', 'protected'},
    special_keywords={'virtual', 'override', 'const', 'static', 'extern', 'inline', 'explicit'},
    call_expression_types=['call_expression', 'subscript_expression'],
    line_comment='//',
    block_comment_start='/*',
    block_comment_end='*/'
)


# Move configuration
MOVE_CONFIG = LanguageConfig(
    language=LanguageType.MOVE,
    file_extensions=['.move'],
    separator='::',
    module_types=['module'],
    function_types=['function_decl'],
    struct_types=['struct_decl'],
    class_types=[],  # Move has no classes
    interface_types=[],  # Move has no interfaces
    enum_types=[],  # Move has no enums
    visibility_keywords={'public', 'entry'},
    special_keywords={'native', 'acquires', 'has', 'key', 'store', 'copy', 'drop'},
    call_expression_types=['call_expression', 'pack_expression'],
    line_comment='//',
    block_comment_start='/*',
    block_comment_end='*/'
)


# Go configuration
GO_CONFIG = LanguageConfig(
    language=LanguageType.GO,
    file_extensions=['.go'],
    separator='.',
    module_types=['package_clause'],
    function_types=['function_declaration', 'method_declaration'],
    struct_types=['type_declaration'],
    class_types=[],  # Go has no classes
    interface_types=['interface_type'],
    enum_types=[],  # Go has no dedicated enums
    visibility_keywords={'public'},  # In Go, uppercase names are public
    special_keywords={'go', 'defer', 'select', 'chan', 'var', 'const', 'type', 'func', 'import', 'package'},
    call_expression_types=['call_expression'],
    line_comment='//',
    block_comment_start='/*',
    block_comment_end='*/'
)


# Configuration mapping
LANGUAGE_CONFIGS: Dict[LanguageType, LanguageConfig] = {
    LanguageType.SOLIDITY: SOLIDITY_CONFIG,
    LanguageType.RUST: RUST_CONFIG,
    LanguageType.CPP: CPP_CONFIG,
    LanguageType.MOVE: MOVE_CONFIG,
    LanguageType.GO: GO_CONFIG,
}


def get_language_config(language: LanguageType) -> LanguageConfig:
    """Get the configuration for a language."""
    return LANGUAGE_CONFIGS[language]


def get_language_by_extension(file_extension: str) -> LanguageType:
    """Determine language by file extension."""
    for language, config in LANGUAGE_CONFIGS.items():
        if file_extension.lower() in config.file_extensions:
            return language
    raise ValueError(f"Unsupported file extension: {file_extension}")


def is_visibility_keyword(language: LanguageType, keyword: str) -> bool:
    """Check whether the keyword represents visibility."""
    config = get_language_config(language)
    return keyword in config.visibility_keywords


def is_special_keyword(language: LanguageType, keyword: str) -> bool:
    """Check whether the keyword is language-specific."""
    config = get_language_config(language)
    return keyword in config.special_keywords
