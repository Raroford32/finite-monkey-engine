"""
Parallel processing utilities for speeding up analysis operations.

This module provides utilities for parallelizing independent steps in the analysis process,
focusing on operations like RAG searches, upstream/downstream analysis, and function searches
that can be executed concurrently to improve overall performance.
"""

import os
from typing import List, Dict, Callable, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import time


class ParallelProcessor:
    """Utility class for executing parallel operations in analysis workflows."""
    
    @staticmethod
    def execute_parallel_tasks(
        task_configs: List[Dict[str, Any]], 
        max_workers: Optional[int] = None,
        timeout: Optional[float] = None,
        ignore_errors: bool = True
    ) -> Dict[str, Any]:
        """
        Execute multiple independent tasks in parallel.
        
        Args:
            task_configs: List of task configurations, each containing:
                - 'name': unique task identifier
                - 'func': callable function to execute
                - 'args': tuple of positional arguments (optional)
                - 'kwargs': dict of keyword arguments (optional)
            max_workers: Maximum number of worker threads (defaults to CPU count)
            timeout: Maximum time to wait for all tasks (optional)
            ignore_errors: If True, continue with other tasks when one fails
            
        Returns:
            Dict mapping task names to their results. Failed tasks have None values.
        """
        if not task_configs:
            return {}
            
        if max_workers is None:
            max_workers = min(len(task_configs), int(os.getenv("MAX_PARALLEL_RAG_WORKERS", 4)))
        
        results = {}
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_name = {}
            for config in task_configs:
                name = config['name']
                func = config['func']
                args = config.get('args', ())
                kwargs = config.get('kwargs', {})
                
                future = executor.submit(func, *args, **kwargs)
                future_to_name[future] = name
            
            # Collect results as they complete
            for future in as_completed(future_to_name, timeout=timeout):
                name = future_to_name[future]
                try:
                    result = future.result()
                    results[name] = result
                except Exception as e:
                    if not ignore_errors:
                        raise e
                    results[name] = None
                    print(f"⚠️ Parallel task '{name}' failed: {str(e)}")
        
        elapsed = time.time() - start_time
        print(f"🚀 Parallel execution completed: {len(results)} tasks in {elapsed:.2f}s")
        
        return results
    
    @staticmethod
    def execute_function_searches_parallel(
        rag_processor, 
        query: str, 
        topk_per_type: int = 2
    ) -> Dict[str, List]:
        """
        Execute function searches of different types in parallel.
        
        Args:
            rag_processor: RAG processor instance
            query: Search query string
            topk_per_type: Number of results per search type
            
        Returns:
            Dict with keys 'name_results', 'content_results', 'natural_results'
        """
        if not rag_processor:
            return {'name_results': [], 'content_results': [], 'natural_results': []}
        
        search_tasks = [
            {
                'name': 'name_search',
                'func': rag_processor.search_functions_by_name,
                'args': (query, topk_per_type)
            },
            {
                'name': 'content_search',
                'func': rag_processor.search_functions_by_content,
                'args': (query, topk_per_type)
            },
            {
                'name': 'natural_search',
                'func': rag_processor.search_functions_by_natural_language,
                'args': (query, topk_per_type)
            }
        ]
        
        results = ParallelProcessor.execute_parallel_tasks(search_tasks)
        
        return {
            'name_results': results.get('name_search', []),
            'content_results': results.get('content_search', []),
            'natural_results': results.get('natural_search', [])
        }
    
    @staticmethod
    def execute_upstream_downstream_parallel(
        planning_processor,
        task_name: str,
        upstream_level: int,
        downstream_level: int,
        upstream_content_func: Callable
    ) -> Dict[str, Optional[str]]:
        """
        Execute upstream and downstream content retrieval in parallel.
        
        Args:
            planning_processor: Planning processor instance
            task_name: Name of the task/function
            upstream_level: Level for upstream analysis
            downstream_level: Level for downstream analysis
            upstream_content_func: Function to get upstream content
            
        Returns:
            Dict with 'upstream_content' and 'downstream_content' keys
        """
        if not planning_processor:
            return {'upstream_content': None, 'downstream_content': None}
        
        upstream_downstream_tasks = [
            {
                'name': 'downstream',
                'func': planning_processor.get_downstream_content_with_call_tree,
                'args': (task_name, downstream_level)
            },
            {
                'name': 'upstream',
                'func': upstream_content_func,
                'args': (task_name, upstream_level, planning_processor)
            }
        ]
        
        results = ParallelProcessor.execute_parallel_tasks(upstream_downstream_tasks)
        
        return {
            'downstream_content': results.get('downstream'),
            'upstream_content': results.get('upstream')
        }
    
    @staticmethod
    def execute_rag_searches_parallel(
        rag_processor,
        query: str,
        task = None,
        round_num: int = 1,
        function_topk: int = 5,
        chunk_topk: int = 3,
        max_chunk_tokens: int = 150000
    ) -> Dict[str, List]:
        """
        Execute multiple RAG searches in parallel for faster information gathering.
        
        Args:
            rag_processor: RAG processor instance
            query: Search query
            task: Task object (optional, for upstream/downstream)
            round_num: Round number for logging
            function_topk: Top-k results for function searches
            chunk_topk: Top-k results for chunk searches
            max_chunk_tokens: Maximum tokens per chunk
            
        Returns:
            Dict containing all search results
        """
        if not rag_processor:
            return {
                'function_results': [],
                'chunk_results': []
            }
        
        # Define parallel tasks for RAG searches
        rag_tasks = [
            {
                'name': 'function_searches',
                'func': ParallelProcessor.execute_function_searches_parallel,
                'args': (rag_processor, query, 2)  # 2 per type for total of ~6 results
            },
            {
                'name': 'chunk_search',
                'func': rag_processor.search_chunks_by_content,
                'args': (query, chunk_topk)
            }
        ]
        
        results = ParallelProcessor.execute_parallel_tasks(rag_tasks)
        
        # Process function search results
        function_search_results = results.get('function_searches', {})
        function_results = []
        
        if function_search_results:
            from ..processors.analysis_processor import AnalysisProcessor
            # Create a temporary processor instance to use the merge method
            temp_processor = AnalysisProcessor({})
            function_results = temp_processor._merge_and_deduplicate_functions(
                function_search_results.get('name_results', []),
                function_search_results.get('content_results', []),
                function_search_results.get('natural_results', []),
                function_topk
            )
        
        # Process chunk search results with token filtering
        chunk_search_results = results.get('chunk_search', [])
        filtered_chunk_results = []
        
        if chunk_search_results:
            for result in chunk_search_results:
                chunk_text = result.get('chunk_text', '')
                # Simple token estimation: ~4 characters per token
                estimated_tokens = len(chunk_text) // 4
                
                if estimated_tokens <= max_chunk_tokens:
                    filtered_chunk_results.append(result)
                else:
                    print(f"  ⚠️ Round {round_num}: Chunk too large ({estimated_tokens} est. tokens), skipped")
        
        return {
            'function_results': function_results,
            'chunk_results': filtered_chunk_results
        }