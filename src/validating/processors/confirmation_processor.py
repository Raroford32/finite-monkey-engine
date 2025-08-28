import os
from typing import List
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

from .analysis_processor import AnalysisProcessor
from ..utils.check_utils import CheckUtils


class ConfirmationProcessor:
    """Vulnerability confirmation processor responsible for executing multi-threaded vulnerability confirmation checks"""
    
    def __init__(self, analysis_processor: AnalysisProcessor):
        self.analysis_processor = analysis_processor
    
    def execute_vulnerability_confirmation(self, task_manager):
        """Execute vulnerability confirmation checks with enhanced parallel processing"""
        all_tasks = task_manager.get_task_list()
        
        # 过滤掉已逻辑删除的任务（short_result为"delete"）
        tasks = [task for task in all_tasks if getattr(task, 'short_result', '') != 'delete']
        
        print(f"📊 任务过滤统计:")
        print(f"   总任务数: {len(all_tasks)}")
        print(f"   已逻辑删除的任务数: {len(all_tasks) - len(tasks)}")
        print(f"   待验证的任务数: {len(tasks)}")
        
        if len(tasks) == 0:
            print("✅ 没有需要验证的任务")
            return []

        # Define number of threads in thread pool, get from env
        max_threads = int(os.getenv("MAX_THREADS_OF_CONFIRMATION", 5))
        
        # 🚀 使用优化的并行处理，支持更好的进度监控和错误处理
        print(f"🚀 开始增强的并行漏洞确认: {len(tasks)} 个任务，{max_threads} 个线程")
        
        completed_tasks = []
        failed_tasks = []
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_task = {
                executor.submit(self._process_single_task_check, task, task_manager): task 
                for task in tasks
            }

            with tqdm(total=len(tasks), desc="Checking vulnerabilities") as pbar:
                for future in as_completed(future_to_task):
                    task = future_to_task[future]
                    try:
                        result = future.result()
                        completed_tasks.append(task)
                    except Exception as e:
                        failed_tasks.append(task)
                        print(f"⚠️ 任务 {task.id} 处理失败: {str(e)}")
                    
                    pbar.update(1)
                    # 更新进度显示
                    pbar.set_postfix({
                        'completed': len(completed_tasks), 
                        'failed': len(failed_tasks),
                        'success_rate': f"{(len(completed_tasks)/(len(completed_tasks)+len(failed_tasks))*100):.1f}%" if (len(completed_tasks)+len(failed_tasks)) > 0 else "0%"
                    })

        print(f"✅ 并行确认完成: {len(completed_tasks)} 成功, {len(failed_tasks)} 失败")
        
        if failed_tasks:
            print(f"⚠️ 失败的任务ID: {[task.id for task in failed_tasks]}")
        
        return tasks
    
    def _process_single_task_check(self, task, task_manager):
        """Process vulnerability check for a single task"""
        print("\n" + "="*80)
        print(f"🔍 Starting to process task ID: {task.id}")
        print("="*80)
        
        # Check if task is already processed
        if CheckUtils.is_task_already_processed(task):
            print("\n🔄 This task has been processed, skipping...")
            return
        
        # Delegate to analysis processor for specific analysis work
        self.analysis_processor.process_task_analysis(task, task_manager) 