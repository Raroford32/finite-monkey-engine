"""
Context module responsible for retrieving and managing analysis context.

This module coordinates context handling during smart-contract auditing, including:
- Context manager (context_manager)
- Call-tree builder (Tree-sitter version)
- RAG processor (rag_processor)
- Business-flow processor (business_flow_processor)
- Function utilities (function_utils)
- Context factory (context_factory)
"""

from .rag_processor import RAGProcessor

# 直接使用Tree-sitter版本的CallTreeBuilder
from tree_sitter_parsing import TreeSitterCallTreeBuilder as CallTreeBuilder

__all__ = [
    'CallTreeBuilder',
    'RAGProcessor'
] 
