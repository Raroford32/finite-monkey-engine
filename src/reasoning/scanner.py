import os
from typing import List
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

from .utils.dialogue_manager import DialogueHistory
from .utils.scan_utils import ScanUtils
from prompt_factory.vul_prompt_common import VulPromptCommon
from openai_api.openai import unified_ask


class VulnerabilityScanner:
    """漏洞扫描器，负责智能合约代码的漏洞扫描"""
    
    def __init__(self, project_audit):
        self.project_audit = project_audit
        # 实例级别的 prompt index 追踪
        self.current_prompt_index = 0
        self.total_prompt_count = len(VulPromptCommon.vul_prompt_common_new().keys())
        # 对话历史管理
        self.dialogue_history = DialogueHistory(project_audit.project_id)
    
    def do_scan(self, task_manager, is_gpt4=False, filter_func=None):
        """执行漏洞扫描"""
        # 获取任务列表
        tasks = task_manager.get_task_list()
        if len(tasks) == 0:
            return []

        # 检查是否启用对话模式
        dialogue_mode = os.getenv("ENABLE_DIALOGUE_MODE", "False").lower() == "true"
        
        if dialogue_mode:
            print("🗣️ 对话模式已启用")
            return self._scan_with_dialogue_mode(tasks, task_manager, filter_func, is_gpt4)
        else:
            print("🔄 标准模式运行中")
            return self._scan_standard_mode(tasks, task_manager, filter_func, is_gpt4)

    def _scan_standard_mode(self, tasks, task_manager, filter_func, is_gpt4):
        """标准模式扫描"""
        max_threads = int(os.getenv("MAX_THREADS_OF_SCAN", 5))
        
        def process_task(task):
            self._process_single_task_standard(task, task_manager, filter_func, is_gpt4)
            
        ScanUtils.execute_parallel_scan(tasks, process_task, max_threads)
        return tasks

    def _scan_with_dialogue_mode(self, tasks, task_manager, filter_func, is_gpt4):
        """对话模式扫描"""
        # 按task.name分组任务
        task_groups = ScanUtils.group_tasks_by_name(tasks)
        
        # 清除历史对话记录
        self.dialogue_history.clear()
        
        # 对每组任务进行处理
        max_threads = int(os.getenv("MAX_THREADS_OF_SCAN", 5))
        
        def process_task_group(group_tasks):
            for task in group_tasks:
                self._process_single_task_dialogue(task, task_manager, filter_func, is_gpt4)
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = []
            for task_name, group_tasks in task_groups.items():
                future = executor.submit(process_task_group, group_tasks)
                futures.append(future)
            
            with tqdm(total=len(task_groups), desc="Processing task groups") as pbar:
                for future in as_completed(futures):
                    future.result()
                    pbar.update(1)
        
        return tasks

    def _process_single_task_standard(self, task, task_manager, filter_func, is_gpt4):
        """标准模式下处理单个任务"""
        # 检查是否已扫描
        if ScanUtils.is_task_already_scanned(task):
            print("\t skipped (scanned)")
            return
            
        # 检查是否需要扫描
        if not ScanUtils.should_scan_task(task, filter_func):
            print("\t skipped (filtered)")
            return

        # 获取要测试的代码
        code_to_be_tested = ScanUtils.get_code_to_test(task)
        
        # 生成提示词 (在COMMON_PROJECT_FINE_GRAINED模式下，直接使用task.recommendation)
        prompt = ScanUtils.get_scan_prompt(code_to_be_tested, task)
        
        # 发送请求并获取响应
        response_vul = unified_ask(prompt)
        print(f"[DEBUG] AI response: {response_vul[:50] if response_vul else 'None'}")
        
        # 处理响应
        response_vul = ScanUtils.process_scan_response(response_vul)
        task_manager.update_result(task.id, response_vul, "", "")

    def _process_single_task_dialogue(self, task, task_manager, filter_func, is_gpt4):
        """对话模式下处理单个任务"""
        # 检查是否已扫描
        if ScanUtils.is_task_already_scanned(task):
            print("\t skipped (scanned)")
            return
            
        # 检查是否需要扫描
        if not ScanUtils.should_scan_task(task, filter_func):
            print("\t skipped (filtered)")
            return

        print("\t to scan")

        # 获取要测试的代码
        code_to_be_tested = ScanUtils.get_code_to_test(task)

        # 在COMMON_PROJECT_FINE_GRAINED模式下，使用task.recommendation作为checklist类型标识
        current_index = None
        if os.getenv("SCAN_MODE", "COMMON_VUL") == "COMMON_PROJECT_FINE_GRAINED":
            # 如果有recommendation，使用它来确定current_index用于对话历史
            if hasattr(task, 'recommendation') and task.recommendation:
                all_checklists = VulPromptCommon.vul_prompt_common_new()
                checklist_keys = list(all_checklists.keys())
                if task.recommendation in checklist_keys:
                    current_index = checklist_keys.index(task.recommendation)
                else:
                    current_index = 0
            else:
                current_index = self.current_prompt_index
                self.current_prompt_index = (current_index + 1) % self.total_prompt_count

        # 获取历史对话
        dialogue_history = self.dialogue_history.get_history(task.name, current_index)
        
        print(f"\n🔄 Task: {task.name}")
        print(f"📊 历史对话数量: {len(dialogue_history)}")
        
        # 打印历史对话长度统计
        if dialogue_history:
            print("\n📈 历史对话长度统计:")
            for i, hist in enumerate(dialogue_history, 1):
                print(f"  第{i}轮对话长度: {len(hist)} 字符")
        
        # 生成基础prompt (在COMMON_PROJECT_FINE_GRAINED模式下，直接使用task.recommendation)
        prompt = ScanUtils.get_scan_prompt(code_to_be_tested, task, current_index)

        # 如果有历史对话，添加到prompt中
        prompt = ScanUtils.add_dialogue_history_to_prompt(prompt, dialogue_history)
        
        print(f"\n📝 基础提示词长度: {len(prompt)} 字符")
        
        # 发送请求并获取响应
        response_vul = unified_ask(prompt)
        print(f"\n✨ 本轮响应长度: {len(response_vul) if response_vul else 0} 字符")
        
        # 保存对话历史
        if response_vul:
            self.dialogue_history.add_response(task.name, current_index, response_vul)
            print(f"✅ 已保存对话历史，当前历史总数: {len(self.dialogue_history.get_history(task.name, current_index))}")
        
        # 处理响应
        response_vul = ScanUtils.process_scan_response(response_vul)
        task_manager.update_result(task.id, response_vul, "", "")
        print("\n" + "="*50 + "\n")  