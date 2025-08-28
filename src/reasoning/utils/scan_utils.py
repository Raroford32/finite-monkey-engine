import os
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

from prompt_factory.prompt_assembler import PromptAssembler
from prompt_factory.vul_prompt_common import VulPromptCommon
from openai_api.openai import detect_vulnerabilities, ask_deepseek, analyze_code_assumptions


class ScanUtils:
    """扫描相关的工具函数类"""
    
    @staticmethod
    def update_recommendation_for_fine_grained(task_manager, task_id: int, current_index: int):
        """为细粒度扫描更新推荐信息"""
        # 在新的实现中，recommendation已经在planning阶段设置好了，这里不需要再更新
        # 但为了兼容性，保留这个方法，只是不执行实际操作
        print(f"[DEBUG🐞]📋Skipping recommendation update - using pre-set recommendation from planning phase")
        pass
    
    @staticmethod
    def is_task_already_scanned(task) -> bool:
        """检查任务是否已经扫描过"""
        result = task.get_result()
        return result is not None and len(result) > 0 and str(result).strip() != "NOT A VUL IN RES no"
    
    @staticmethod
    def should_scan_task(task, filter_func) -> bool:
        """判断是否应该扫描该任务"""
        return filter_func is None or filter_func(task)
    
    @staticmethod
    def get_code_to_test(task):
        """获取要测试的代码"""
        business_flow_code = task.business_flow_code
        if_business_flow_scan = task.if_business_flow_scan
        function_code = task.content
        
        return business_flow_code if if_business_flow_scan == "1" else function_code
    
    @staticmethod
    def process_scan_response(response_vul: str) -> str:
        """处理扫描响应"""
        return response_vul if response_vul is not None else "no"
    
    @staticmethod
    def execute_parallel_scan(tasks: List, process_func, max_threads: int = 5):
        """执行并行扫描 - 改进版本，支持更好的错误处理和进度监控"""
        if not tasks:
            return
        
        # 支持环境变量配置最大线程数
        max_threads = min(max_threads, int(os.getenv("MAX_THREADS_OF_SCAN", max_threads)))
        
        print(f"🚀 开始并行扫描: {len(tasks)} 个任务，{max_threads} 个并发线程")
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = [executor.submit(process_func, task) for task in tasks]
            
            with tqdm(total=len(tasks), desc="Processing tasks") as pbar:
                completed = 0
                failed = 0
                
                for future in as_completed(futures):
                    try:
                        future.result()
                        completed += 1
                    except Exception as e:
                        failed += 1
                        print(f"⚠️ 任务处理失败: {str(e)}")
                    
                    pbar.update(1)
                    pbar.set_postfix({
                        'completed': completed, 
                        'failed': failed,
                        'success_rate': f"{(completed/(completed+failed)*100):.1f}%" if (completed+failed) > 0 else "0%"
                    })
        
        print(f"✅ 并行扫描完成: {completed} 成功, {failed} 失败")
    
    @staticmethod
    def execute_parallel_business_flow_analysis(functions_to_check: List, 
                                               flow_analysis_func, 
                                               max_workers: int = None) -> List:
        """
        并行执行业务流分析，适用于大量函数的独立分析
        
        Args:
            functions_to_check: 要分析的函数列表
            flow_analysis_func: 单个函数的业务流分析函数
            max_workers: 最大工作线程数
            
        Returns:
            分析结果列表
        """
        if not functions_to_check:
            return []
        
        if max_workers is None:
            max_workers = min(len(functions_to_check), int(os.getenv("MAX_THREADS_OF_SCAN", 5)))
        
        print(f"🔄 开始并行业务流分析: {len(functions_to_check)} 个函数，{max_workers} 个线程")
        
        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_func = {
                executor.submit(flow_analysis_func, func): func 
                for func in functions_to_check
            }
            
            with tqdm(total=len(functions_to_check), desc="Analyzing business flows") as pbar:
                for future in as_completed(future_to_func):
                    func = future_to_func[future]
                    try:
                        result = future.result()
                        if result:  # 只添加有效结果
                            results.append(result)
                    except Exception as e:
                        print(f"⚠️ 函数 {getattr(func, 'name', 'unknown')} 业务流分析失败: {str(e)}")
                    
                    pbar.update(1)
        
        print(f"✅ 并行业务流分析完成: {len(results)} 个有效结果")
        return results
    
    @staticmethod
    def group_tasks_by_name(tasks: List) -> Dict[str, List]:
        """按任务名称分组任务"""
        task_groups = {}
        for task in tasks:
            task_groups.setdefault(task.name, []).append(task)
        return task_groups
    
    @staticmethod
    def add_dialogue_history_to_prompt(prompt: str, dialogue_history: List[str]) -> str:
        """将对话历史添加到提示词中"""
        if dialogue_history:
            history_text = "\n\nPreviously Found Vulnerabilities:\n" + "\n".join(dialogue_history)
            prompt += history_text + "\n\nExcluding these vulnerabilities, please continue searching for other potential vulnerabilities."
        return prompt 