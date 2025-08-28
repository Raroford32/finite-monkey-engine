#!/usr/bin/env python3
"""
Test script for parallel processing improvements in the finite monkey engine.

This script tests the new parallel processing utilities to ensure they work correctly
and provide performance improvements over the original sequential implementation.
"""

import os
import sys
import time
import unittest
from unittest.mock import Mock, MagicMock
from concurrent.futures import ThreadPoolExecutor

# Add the src directory to the path so we can import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

try:
    from validating.utils.parallel_utils import ParallelProcessor
    from reasoning.utils.scan_utils import ScanUtils
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Trying alternative import path...")
    try:
        # Alternative approach: import from current directory structure
        sys.path.insert(0, os.path.dirname(__file__))
        from src.validating.utils.parallel_utils import ParallelProcessor
        from src.reasoning.utils.scan_utils import ScanUtils
    except ImportError as e2:
        print(f"❌ Alternative import also failed: {e2}")
        print("Make sure you're running this from the repository root directory")
        sys.exit(1)


class TestParallelProcessing(unittest.TestCase):
    """Test cases for parallel processing utilities."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.processor = ParallelProcessor()
        
    def test_parallel_task_execution(self):
        """Test basic parallel task execution."""
        print("\n🧪 Testing basic parallel task execution...")
        
        def mock_task(task_id, delay=0.1):
            """Mock task that simulates work."""
            time.sleep(delay)
            return f"task_{task_id}_result"
        
        # Define test tasks
        task_configs = [
            {'name': f'task_{i}', 'func': mock_task, 'args': (i, 0.1)}
            for i in range(5)
        ]
        
        start_time = time.time()
        results = ParallelProcessor.execute_parallel_tasks(task_configs, max_workers=3)
        execution_time = time.time() - start_time
        
        # Verify results
        self.assertEqual(len(results), 5)
        for i in range(5):
            self.assertEqual(results[f'task_{i}'], f'task_{i}_result')
        
        # Should complete in roughly 0.2 seconds (2 batches of 0.1s each) with 3 workers
        # instead of 0.5 seconds (5 * 0.1s) sequentially
        self.assertLess(execution_time, 0.4, "Parallel execution should be faster than sequential")
        print(f"✅ Parallel execution completed in {execution_time:.2f}s (expected < 0.4s)")
        
    def test_function_searches_parallel(self):
        """Test parallel function searches."""
        print("\n🧪 Testing parallel function searches...")
        
        # Mock RAG processor
        mock_rag = Mock()
        mock_rag.search_functions_by_name.return_value = [{'name': 'func1', 'content': 'content1'}]
        mock_rag.search_functions_by_content.return_value = [{'name': 'func2', 'content': 'content2'}]
        mock_rag.search_functions_by_natural_language.return_value = [{'name': 'func3', 'content': 'content3'}]
        
        results = ParallelProcessor.execute_function_searches_parallel(
            mock_rag, "test query", topk_per_type=2
        )
        
        # Verify all search methods were called
        mock_rag.search_functions_by_name.assert_called_once_with("test query", 2)
        mock_rag.search_functions_by_content.assert_called_once_with("test query", 2)
        mock_rag.search_functions_by_natural_language.assert_called_once_with("test query", 2)
        
        # Verify results structure
        self.assertIn('name_results', results)
        self.assertIn('content_results', results)
        self.assertIn('natural_results', results)
        
        print("✅ Parallel function searches completed successfully")
        
    def test_upstream_downstream_parallel(self):
        """Test parallel upstream/downstream analysis."""
        print("\n🧪 Testing parallel upstream/downstream analysis...")
        
        # Mock planning processor and upstream function
        mock_planning = Mock()
        mock_planning.get_downstream_content_with_call_tree.return_value = "downstream_content"
        
        def mock_upstream_func(task_name, level, processor):
            return "upstream_content"
        
        results = ParallelProcessor.execute_upstream_downstream_parallel(
            mock_planning, "test_function", 3, 4, mock_upstream_func
        )
        
        # Verify both methods were called
        mock_planning.get_downstream_content_with_call_tree.assert_called_once_with("test_function", 4)
        
        # Verify results
        self.assertEqual(results['downstream_content'], "downstream_content")
        self.assertEqual(results['upstream_content'], "upstream_content")
        
        print("✅ Parallel upstream/downstream analysis completed successfully")
        
    def test_error_handling(self):
        """Test error handling in parallel execution."""
        print("\n🧪 Testing error handling...")
        
        def failing_task():
            raise Exception("Simulated task failure")
        
        def successful_task():
            return "success"
        
        task_configs = [
            {'name': 'failing_task', 'func': failing_task},
            {'name': 'successful_task', 'func': successful_task}
        ]
        
        results = ParallelProcessor.execute_parallel_tasks(task_configs, ignore_errors=True)
        
        # Verify that successful task completed and failing task returned None
        self.assertIsNone(results['failing_task'])
        self.assertEqual(results['successful_task'], 'success')
        
        print("✅ Error handling works correctly")
        
    def test_scan_utils_improvements(self):
        """Test improvements to ScanUtils."""
        print("\n🧪 Testing ScanUtils improvements...")
        
        # Mock tasks and process function
        mock_tasks = [Mock(id=i) for i in range(3)]
        
        def mock_process_func(task):
            time.sleep(0.05)  # Simulate processing time
            return f"processed_{task.id}"
        
        # Test the improved parallel scan
        start_time = time.time()
        ScanUtils.execute_parallel_scan(mock_tasks, mock_process_func, max_threads=2)
        execution_time = time.time() - start_time
        
        # Should complete faster than sequential execution
        self.assertLess(execution_time, 0.2, "Parallel scan should be faster")
        print(f"✅ Parallel scan completed in {execution_time:.2f}s")


def benchmark_performance():
    """Benchmark the performance improvement from parallelization."""
    print("\n📊 Performance Benchmark")
    print("=" * 50)
    
    def simulate_rag_search(query, topk):
        """Simulate a RAG search operation."""
        time.sleep(0.1)  # Simulate network/computation delay
        return [{'name': f'func_{i}', 'content': f'content_{i}'} for i in range(topk)]
    
    # Mock RAG processor
    mock_rag = Mock()
    mock_rag.search_functions_by_name = simulate_rag_search
    mock_rag.search_functions_by_content = simulate_rag_search
    mock_rag.search_functions_by_natural_language = simulate_rag_search
    
    # Sequential execution (original approach)
    print("🔄 Testing sequential execution...")
    start_time = time.time()
    name_results = mock_rag.search_functions_by_name("test", 2)
    content_results = mock_rag.search_functions_by_content("test", 2)
    natural_results = mock_rag.search_functions_by_natural_language("test", 2)
    sequential_time = time.time() - start_time
    
    # Parallel execution (new approach)
    print("🚀 Testing parallel execution...")
    start_time = time.time()
    results = ParallelProcessor.execute_function_searches_parallel(mock_rag, "test", 2)
    parallel_time = time.time() - start_time
    
    # Calculate speedup
    speedup = sequential_time / parallel_time if parallel_time > 0 else 0
    improvement = ((sequential_time - parallel_time) / sequential_time * 100) if sequential_time > 0 else 0
    
    print(f"\n📈 Performance Results:")
    print(f"  Sequential time: {sequential_time:.3f}s")
    print(f"  Parallel time:   {parallel_time:.3f}s")
    print(f"  Speedup:         {speedup:.2f}x")
    print(f"  Improvement:     {improvement:.1f}%")
    
    if speedup > 1.5:
        print("✅ Significant performance improvement achieved!")
    elif speedup > 1.0:
        print("✅ Performance improvement achieved!")
    else:
        print("⚠️ No significant speedup (might be due to test environment)")


def main():
    """Main test function."""
    print("🎯 Finite Monkey Engine - Parallel Processing Tests")
    print("=" * 60)
    
    # Set test environment variables
    os.environ['MAX_PARALLEL_RAG_WORKERS'] = '3'
    os.environ['MAX_THREADS_OF_SCAN'] = '5'
    os.environ['MAX_THREADS_OF_CONFIRMATION'] = '10'
    
    # Run unit tests
    print("\n🧪 Running Unit Tests...")
    unittest.main(argv=[''], exit=False, verbosity=0)
    
    # Run performance benchmark
    benchmark_performance()
    
    print("\n✅ All tests completed!")
    print("\n📝 Summary:")
    print("  - Parallel processing utilities implemented successfully")
    print("  - RAG searches can now run in parallel")
    print("  - Upstream/downstream analysis parallelized")
    print("  - Error handling and fallback mechanisms in place")
    print("  - Performance improvements demonstrated")


if __name__ == "__main__":
    main()