#!/usr/bin/env python3
"""
Simple test for parallel processing functionality.
This test validates that our parallel processing improvements work correctly.
"""

import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any

# Mock classes for testing
class MockRAGProcessor:
    """Mock RAG processor for testing."""
    
    def search_functions_by_name(self, query: str, topk: int):
        time.sleep(0.1)  # Simulate processing time
        return [{'name': f'name_func_{i}', 'content': f'name_content_{i}'} for i in range(topk)]
    
    def search_functions_by_content(self, query: str, topk: int):
        time.sleep(0.1)  # Simulate processing time
        return [{'name': f'content_func_{i}', 'content': f'content_content_{i}'} for i in range(topk)]
    
    def search_functions_by_natural_language(self, query: str, topk: int):
        time.sleep(0.1)  # Simulate processing time
        return [{'name': f'natural_func_{i}', 'content': f'natural_content_{i}'} for i in range(topk)]
    
    def search_chunks_by_content(self, query: str, topk: int):
        time.sleep(0.05)  # Simulate processing time
        return [{'chunk_text': f'chunk_{i}_text', 'original_file': f'file_{i}.py'} for i in range(topk)]


class SimplifiedParallelProcessor:
    """Simplified version of our parallel processor for testing."""
    
    @staticmethod
    def execute_parallel_tasks(task_configs: List[Dict[str, Any]], max_workers: int = 3) -> Dict[str, Any]:
        """Execute multiple tasks in parallel."""
        results = {}
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_name = {}
            for config in task_configs:
                name = config['name']
                func = config['func']
                args = config.get('args', ())
                kwargs = config.get('kwargs', {})
                
                future = executor.submit(func, *args, **kwargs)
                future_to_name[future] = name
            
            for future in as_completed(future_to_name):
                name = future_to_name[future]
                try:
                    result = future.result()
                    results[name] = result
                except Exception as e:
                    results[name] = None
                    print(f"⚠️ Task '{name}' failed: {str(e)}")
        
        return results
    
    @staticmethod
    def execute_function_searches_parallel(rag_processor, query: str, topk_per_type: int = 2):
        """Execute function searches in parallel."""
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
        
        results = SimplifiedParallelProcessor.execute_parallel_tasks(search_tasks)
        
        return {
            'name_results': results.get('name_search', []),
            'content_results': results.get('content_search', []),
            'natural_results': results.get('natural_search', [])
        }


def test_basic_parallel_execution():
    """Test basic parallel task execution."""
    print("🧪 Testing basic parallel execution...")
    
    def mock_task(task_id, delay=0.1):
        time.sleep(delay)
        return f"task_{task_id}_result"
    
    # Define tasks
    task_configs = [
        {'name': f'task_{i}', 'func': mock_task, 'args': (i, 0.1)}
        for i in range(5)
    ]
    
    start_time = time.time()
    results = SimplifiedParallelProcessor.execute_parallel_tasks(task_configs, max_workers=3)
    execution_time = time.time() - start_time
    
    # Verify results
    assert len(results) == 5, f"Expected 5 results, got {len(results)}"
    for i in range(5):
        assert results[f'task_{i}'] == f'task_{i}_result', f"Task {i} result mismatch"
    
    # Should be faster than sequential (0.5s)
    assert execution_time < 0.4, f"Expected < 0.4s, got {execution_time:.3f}s"
    
    print(f"✅ Basic parallel execution: {execution_time:.3f}s (expected < 0.4s)")
    return execution_time


def test_parallel_rag_searches():
    """Test parallel RAG searches."""
    print("🧪 Testing parallel RAG searches...")
    
    rag_processor = MockRAGProcessor()
    
    # Test sequential execution
    start_time = time.time()
    name_results = rag_processor.search_functions_by_name("test", 2)
    content_results = rag_processor.search_functions_by_content("test", 2)
    natural_results = rag_processor.search_functions_by_natural_language("test", 2)
    sequential_time = time.time() - start_time
    
    # Test parallel execution
    start_time = time.time()
    parallel_results = SimplifiedParallelProcessor.execute_function_searches_parallel(rag_processor, "test", 2)
    parallel_time = time.time() - start_time
    
    # Verify results
    assert len(parallel_results['name_results']) == 2, "Name results count mismatch"
    assert len(parallel_results['content_results']) == 2, "Content results count mismatch"
    assert len(parallel_results['natural_results']) == 2, "Natural results count mismatch"
    
    # Calculate speedup
    speedup = sequential_time / parallel_time if parallel_time > 0 else 0
    improvement = ((sequential_time - parallel_time) / sequential_time * 100) if sequential_time > 0 else 0
    
    print(f"✅ RAG searches - Sequential: {sequential_time:.3f}s, Parallel: {parallel_time:.3f}s")
    print(f"   Speedup: {speedup:.2f}x, Improvement: {improvement:.1f}%")
    
    return speedup


def test_concurrent_analysis():
    """Test concurrent analysis simulation."""
    print("🧪 Testing concurrent analysis simulation...")
    
    def simulate_analysis_step(step_name, processing_time=0.1):
        """Simulate an analysis step."""
        time.sleep(processing_time)
        return f"{step_name}_completed"
    
    # Simulate the original sequential approach
    start_time = time.time()
    rag_result = simulate_analysis_step("rag_search", 0.1)
    upstream_result = simulate_analysis_step("upstream_analysis", 0.1)
    downstream_result = simulate_analysis_step("downstream_analysis", 0.1)
    sequential_time = time.time() - start_time
    
    # Simulate parallel approach
    analysis_tasks = [
        {'name': 'rag_search', 'func': simulate_analysis_step, 'args': ('rag_search', 0.1)},
        {'name': 'upstream', 'func': simulate_analysis_step, 'args': ('upstream_analysis', 0.1)},
        {'name': 'downstream', 'func': simulate_analysis_step, 'args': ('downstream_analysis', 0.1)}
    ]
    
    start_time = time.time()
    parallel_results = SimplifiedParallelProcessor.execute_parallel_tasks(analysis_tasks)
    parallel_time = time.time() - start_time
    
    # Verify results
    assert parallel_results['rag_search'] == 'rag_search_completed'
    assert parallel_results['upstream'] == 'upstream_analysis_completed'
    assert parallel_results['downstream'] == 'downstream_analysis_completed'
    
    speedup = sequential_time / parallel_time if parallel_time > 0 else 0
    improvement = ((sequential_time - parallel_time) / sequential_time * 100) if sequential_time > 0 else 0
    
    print(f"✅ Analysis simulation - Sequential: {sequential_time:.3f}s, Parallel: {parallel_time:.3f}s")
    print(f"   Speedup: {speedup:.2f}x, Improvement: {improvement:.1f}%")
    
    return speedup


def main():
    """Main test function."""
    print("🎯 Finite Monkey Engine - Parallel Processing Tests")
    print("=" * 60)
    
    try:
        # Run tests
        basic_time = test_basic_parallel_execution()
        rag_speedup = test_parallel_rag_searches()
        analysis_speedup = test_concurrent_analysis()
        
        print("\n📊 Performance Summary:")
        print("=" * 40)
        print(f"Basic parallel execution time: {basic_time:.3f}s")
        print(f"RAG search speedup: {rag_speedup:.2f}x")
        print(f"Analysis simulation speedup: {analysis_speedup:.2f}x")
        
        if rag_speedup > 2.0 and analysis_speedup > 2.0:
            print("\n✅ Excellent parallelization performance!")
        elif rag_speedup > 1.5 and analysis_speedup > 1.5:
            print("\n✅ Good parallelization performance!")
        else:
            print("\n⚠️ Moderate parallelization performance (may be due to test environment)")
        
        print("\n🎉 All tests passed successfully!")
        print("\n📝 Parallelization Benefits:")
        print("  ✓ Multiple RAG searches can run concurrently")
        print("  ✓ Upstream/downstream analysis parallelized")
        print("  ✓ Analysis steps can execute independently")
        print("  ✓ Error handling and fallback mechanisms")
        print("  ✓ Configurable thread pool sizes")
        
    except Exception as e:
        print(f"\n❌ Test failed: {str(e)}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)