import os
import time
import json
from datetime import datetime
from typing import List, Tuple, Dict, Any
import tiktoken

from dao.entity import Project_Task

from ..utils.check_utils import CheckUtils
from prompt_factory.prompt_assembler import PromptAssembler
from openai_api.openai import analyze_code_assumptions, extract_structured_json


class AnalysisProcessor:
    """Analysis processor responsible for executing specific vulnerability analysis logic (支持RAG选择)"""
    
    def __init__(self, context_data: Dict[str, Any]):
        """
        初始化分析处理器
        
        Args:
            context_data: 包含项目数据的字典，包括functions, functions_to_check等
        """
        self.context_data = context_data
        self.functions = context_data.get('functions', [])
        self.functions_to_check = context_data.get('functions_to_check', [])
        self.call_trees = context_data.get('call_trees', [])
        self.project_id = context_data.get('project_id', '')
        self.project_path = context_data.get('project_path', '')
        
        # 初始化RAG处理器与内存（如果可用）
        self.rag_processor = None
        self.agent_memory = None
        self._initialize_rag_processor()
    
    def _initialize_rag_processor(self):
        """初始化RAG处理器与AgentMemory"""
        try:
            from context.rag_processor import RAGProcessor
            from agentic.memory import AgentMemory
            # 获取project_audit对象
            project_audit = self.context_data.get('project_audit')
            if not project_audit:
                self.rag_processor = None
                self.agent_memory = None
                return
            
            # 使用正确的参数初始化RAG处理器 
            import os as _os
            lancedb_path = _os.getenv("LANCEDB_PATH", "./src/codebaseQA/lancedb")
            self.rag_processor = RAGProcessor(
                project_audit,  # 🔧 使用完整的project_audit对象，而不是functions_to_check
                lancedb_path, 
                self.project_id
            )
            self.agent_memory = AgentMemory(self.rag_processor)
        except Exception as e:
            import traceback
            self.rag_processor = None
            self.agent_memory = None

    def _count_tokens(self, text: str, model: str = "gpt-4") -> int:
        """计算文本的token数量
        
        Args:
            text: 要计算的文本
            model: 模型名称，默认gpt-4
            
        Returns:
            token数量
        """
        try:
            encoding = tiktoken.encoding_for_model(model)
            return len(encoding.encode(text))
        except Exception:
            # 如果失败，使用简单估算：大约4字符=1token
            return len(text) // 4

    def get_available_rag_types(self) -> Dict[str, str]:
        """获取可用的RAG类型列表及其描述"""
        if not self.rag_processor:
            return {}
        
        return {
            # 基础RAG类型
            'name': '名字检索 - 基于函数名称的精确匹配，适合查找特定函数',
            'content': '内容检索 - 基于函数源代码内容的语义相似性，适合查找相似功能的代码',
            'natural': '自然语言检索 - 基于AI生成的功能描述的语义理解，适合描述性查询',
            
            # 关系型RAG类型
            'upstream': '上游函数检索 - 基于调用此函数的上游函数内容，适合查找调用链上游',
            'downstream': '下游函数检索 - 基于此函数调用的下游函数内容，适合查找调用链下游',
            
            # 专门的关系表RAG类型
            'upstream_natural': '上游自然语言关系检索 - 基于上游函数的自然语言描述，适合理解上游逻辑',
            'downstream_natural': '下游自然语言关系检索 - 基于下游函数的自然语言描述，适合理解下游影响',
            'upstream_content': '上游内容关系检索 - 基于上游函数的代码内容，适合代码层面的上游分析',
            'downstream_content': '下游内容关系检索 - 基于下游函数的代码内容，适合代码层面的下游分析',
            
            # 文件级RAG类型
            'file_content': '文件内容检索 - 基于整个文件的内容，适合文件级别的分析',
            'file_natural': '文件自然语言检索 - 基于文件的自然语言描述，适合文件功能理解'
        }

    def ask_llm_to_choose_rag_for_validation(self, vulnerability_report: str, validation_question: str, context_info: str = "") -> Dict[str, Any]:
        """让大模型选择RAG类型进行漏洞验证
        
        Args:
            vulnerability_report: 漏洞报告内容
            validation_question: 验证问题
            context_info: 上下文信息
            
        Returns:
            Dict包含选择的RAG类型、查询内容和RAG结果
        """
        if not self.rag_processor:
            return {
                'rag_chosen': None,
                'query_used': None,
                'rag_results': [],
                'reason': 'RAG处理器不可用'
            }
        
        # 获取可用的RAG类型
        rag_types = self.get_available_rag_types()
        
        # 构建提示，让大模型选择RAG类型
        rag_selection_prompt = f"""你正在进行智能合约漏洞验证。需要根据漏洞报告和验证问题，选择最合适的RAG检索类型来获取相关信息进行验证。

**漏洞报告**：
{vulnerability_report}

**验证问题**：
{validation_question}

**当前上下文**：
{context_info}

**可用的RAG检索类型**：
{chr(10).join([f'- {k}: {v}' for k, v in rag_types.items()])}

**请分析：**
1. 要验证这个漏洞，最需要什么类型的相关信息？
2. 应该选择哪种RAG类型来获取这些信息？
3. 应该使用什么查询内容进行检索？

**选择建议**：
- 如果需要验证函数调用关系，选择upstream/downstream相关的RAG
- 如果需要查找相似的漏洞模式，选择content或natural RAG
- 如果需要理解业务逻辑，选择natural相关的RAG
- 如果需要验证特定函数行为，选择name或content RAG

请用JSON格式回答：
{{
    "rag_type": "选择的RAG类型名称",
    "query_content": "用于检索的具体查询内容",
    "reason": "选择此RAG类型的详细原因",
    "validation_focus": "验证的重点是什么",
    "backup_rag_type": "备选RAG类型（可选）",
    "backup_query": "备选查询内容（可选）"
}}

只返回JSON，不要其他解释。"""

        try:
            # 询问大模型选择RAG类型
            response = extract_structured_json(rag_selection_prompt)
            
            if not response:
                return {
                    'rag_chosen': None,
                    'query_used': None,
                    'rag_results': [],
                    'reason': '大模型未返回RAG选择'
                }
            
            rag_choice = json.loads(response) if isinstance(response, str) else response
            
            chosen_rag = rag_choice.get('rag_type', 'content')  # 默认使用content
            query_content = rag_choice.get('query_content', validation_question)
            reason = rag_choice.get('reason', '默认选择')
            validation_focus = rag_choice.get('validation_focus', '常规验证')
            

            
            # 根据选择执行相应的RAG查询
            rag_results = self._execute_rag_query(chosen_rag, query_content)
            
            # 如果主要RAG没有结果，尝试备选方案
            if not rag_results and rag_choice.get('backup_rag_type'):
                backup_rag = rag_choice.get('backup_rag_type')
                backup_query = rag_choice.get('backup_query', query_content)
                rag_results = self._execute_rag_query(backup_rag, backup_query)
                chosen_rag = backup_rag
                query_content = backup_query
            
            return {
                'rag_chosen': chosen_rag,
                'query_used': query_content,
                'rag_results': rag_results,
                'reason': reason,
                'validation_focus': validation_focus,
                'llm_choice': rag_choice
            }
            
        except Exception as e:
            # 回退到简单的content搜索
            rag_results = self._execute_rag_query('content', validation_question)
            return {
                'rag_chosen': 'content',
                'query_used': validation_question,
                'rag_results': rag_results,
                'reason': f'RAG选择失败，回退到默认: {str(e)}'
            }

    def _execute_rag_query(self, rag_type: str, query: str, k: int = 5) -> List[Dict]:
        """执行指定类型的RAG查询
        
        Args:
            rag_type: RAG类型
            query: 查询内容
            k: 返回结果数量
            
        Returns:
            List[Dict]: RAG查询结果
        """
        if not self.rag_processor:
            return []
        
        try:
            # 根据RAG类型调用相应的搜索方法
            if rag_type == 'name':
                return self.rag_processor.search_functions_by_name(query, k)
            elif rag_type == 'content':
                return self.rag_processor.search_functions_by_content(query, k)
            elif rag_type == 'natural':
                return self.rag_processor.search_functions_by_natural_language(query, k)
            elif rag_type == 'upstream':
                return self.rag_processor.search_functions_by_upstream(query, k)
            elif rag_type == 'downstream':
                return self.rag_processor.search_functions_by_downstream(query, k)
            elif rag_type == 'upstream_natural':
                return self.rag_processor.search_relationships_by_upstream_natural(query, k)
            elif rag_type == 'downstream_natural':
                return self.rag_processor.search_relationships_by_downstream_natural(query, k)
            elif rag_type == 'upstream_content':
                return self.rag_processor.search_relationships_by_upstream_content(query, k)
            elif rag_type == 'downstream_content':
                return self.rag_processor.search_relationships_by_downstream_content(query, k)
            elif rag_type == 'file_content':
                return self.rag_processor.search_files_by_content(query, k)
            elif rag_type == 'file_natural':
                return self.rag_processor.search_files_by_natural_language(query, k)
            else:
                return self.rag_processor.search_functions_by_content(query, k)
                
        except Exception as e:
            return []

    def extract_required_info(self, response_text: str) -> List[str]:
        """提取需要进一步分析的信息（增强RAG支持）"""
        # 首先尝试使用大模型提取关键信息
        try:
            extract_prompt = f"""从以下漏洞分析报告中提取需要进一步验证或分析的关键信息点：

{response_text}

请提取：
1. 需要验证的函数调用关系
2. 需要确认的代码逻辑
3. 需要查找的相关函数或合约
4. 需要分析的业务流程
5. 其他需要进一步分析的要点

请用JSON格式返回：
{{
    "required_info": [
        "信息点1的具体描述",
        "信息点2的具体描述"
    ],
    "analysis_type": "需要的分析类型（如函数关系分析、逻辑验证等）",
    "priority": "high/medium/low"
}}

只返回JSON，不要其他解释。"""

            response = extract_structured_json(extract_prompt)
            if response:
                extracted = json.loads(response) if isinstance(response, str) else response
                return extracted.get('required_info', [])
        except Exception as e:
            pass
        
        # 回退到简化的实现
        required_info = []
        keywords = ['需要进一步', '更多信息', '需要查看', '需要确认', '缺少信息', '验证', '分析']
        
        for keyword in keywords:
            if keyword in response_text:
                sentences = response_text.split('。')
                for sentence in sentences:
                    if keyword in sentence:
                        required_info.append(sentence.strip())
                        break
        
        return required_info

    def get_additional_context_with_rag(self, required_info: List[str], original_report: str = "") -> str:
        """使用RAG获取额外的上下文信息
        
        Args:
            required_info: 需要的信息列表
            original_report: 原始报告内容
            
        Returns:
            str: 增强的上下文信息
        """
        if not required_info:
            return "未找到需要进一步分析的信息"
        
        enhanced_context_parts = []
        
        for i, info in enumerate(required_info, 1):
            try:
                
                # 为每个信息点让大模型选择RAG类型
                validation_question = f"需要验证或分析：{info}"
                rag_result = self.ask_llm_to_choose_rag_for_validation(original_report, validation_question, info)
                
                enhanced_context_parts.append(f"\n=== 信息点 {i} ===")
                enhanced_context_parts.append(f"需要分析: {info}")
                
                if rag_result.get('rag_chosen'):
                    enhanced_context_parts.append(f"使用RAG类型: {rag_result['rag_chosen']}")
                    enhanced_context_parts.append(f"验证重点: {rag_result.get('validation_focus', '常规验证')}")
                    
                    if rag_result.get('rag_results'):
                        enhanced_context_parts.append(f"找到 {len(rag_result['rag_results'])} 个相关结果:")
                        for j, result in enumerate(rag_result['rag_results'][:2], 1):  # 只显示前2个
                            if isinstance(result, dict):
                                func_name = result.get('name', result.get('function_name', 'Unknown'))
                                content_preview = result.get('content', '')[:100] if result.get('content') else ''
                                enhanced_context_parts.append(f"  {j}. {func_name}: {content_preview}...")
                    else:
                        enhanced_context_parts.append("  未找到直接相关的代码")
                else:
                    enhanced_context_parts.append("  RAG查询不可用，使用传统分析")
                    # 使用传统方法查找相关函数
                    traditional_context = self._get_traditional_context(info)
                    if traditional_context:
                        enhanced_context_parts.append(f"  传统分析结果: {traditional_context}")
                
            except Exception as e:
                enhanced_context_parts.append(f"  处理失败: {str(e)}")
        
        return '\n'.join(enhanced_context_parts)

    def _get_traditional_context(self, info: str) -> str:
        """传统方法获取上下文（作为RAG的备选）"""
        context_parts = []
        info_lower = info.lower()
        
        # 在functions中查找相关信息
        for func in self.functions_to_check:
            func_content = func.get('content', '').lower()
            func_name = func.get('name', '')
            
            # 简单的关键词匹配
            if any(keyword in func_content for keyword in info_lower.split()):
                context_parts.append(f"相关函数: {func_name}")
                if len(context_parts) >= 3:  # 限制结果数量
                    break
        
        return '; '.join(context_parts) if context_parts else "未找到相关函数"

    def get_additional_internet_info(self, required_info: List[str]) -> str:
        """获取网络信息（简化实现）"""
        if required_info:
            return f"网络搜索结果：找到{len(required_info)}个相关信息点（简化实现）"
        return ""

    def get_additional_context(self, required_info: List[str]) -> str:
        """获取额外上下文（向后兼容方法）"""
        return self.get_additional_context_with_rag(required_info)


    
    def process_task_analysis(self, task:Project_Task,task_manager):
        """Agent化的三轮漏洞检测流程"""
        import json
        from datetime import datetime
        
        start_time = time.time()
        logs = []
        
        logs.append(f"开始时间: {datetime.utcnow().isoformat()}")
        
        # 获取规则和业务流代码
        vulnerability_result = task.result
        business_flow_code = task.business_flow_code
        
        logs.append(f"规则类型: {task.rule_key}")
        logs.append(f"代码长度: {len(business_flow_code)} 字符")
        
        # 执行三轮独立检测
        round_results = []
        
        for round_num in range(1, 4):  # 三轮检测
            logs.append(f"开始第 {round_num} 轮检测")
            
            try:
                round_result = self._execute_single_detection_round(
                    vulnerability_result, business_flow_code, task, round_num, logs
                )
                round_results.append(round_result)
                logs.append(f"第 {round_num} 轮结果: {round_result}")
                
                # 🔧 如果任何一轮得到 'no' 结果，直接跳出循环，不执行后续轮次
                if round_result == 'no':
                    print(f"🚫 [Round {round_num}] 检测到 'no' 结果，跳过剩余轮次")
                    logs.append(f"第 {round_num} 轮: 检测到 'no' 结果，跳过剩余轮次")
                    break
                
            except Exception as e:
                logs.append(f"第 {round_num} 轮失败: {str(e)}")
                round_results.append("not_sure")
        
        # 汇总三轮结果
        final_short_result, final_detailed_result = self._aggregate_round_results(round_results, logs)
        
        # 计算处理时间
        end_time = time.time()
        process_time = round(end_time - start_time, 2)
        
        logs.append(f"最终简短结果: {final_short_result}")
        logs.append(f"处理耗时: {process_time}秒")
        logs.append(f"结束时间: {datetime.utcnow().isoformat()}")
        
        # 🔍 检查是否有任意轮次失败，决定是否保存
        not_sure_count = sum(1 for result in round_results if result == 'not_sure')
        valid_results_count = len(round_results) - not_sure_count
        
        # ⚠️ 只要有任意一个轮次失败(not_sure)，就不保存validation结果
        if not_sure_count > 0:
            logs.append("⚠️ 有轮次失败，不保存validation结果")
            
            # 只保存失败日志到scan_record，不设置short_result
            scan_data = {
                'logs': logs,
                'round_results': round_results,
                'process_time': process_time,
                'timestamp': datetime.utcnow().isoformat(),
                'rounds_count': 3,
                'validation_failed': True,
                'failed_rounds': not_sure_count,
                'original_reasoning_result': task.result
            }
            task.scan_record = json.dumps(scan_data, ensure_ascii=False)
            
            # 更新数据库但不设置short_result
            task_manager.save_task(task)
            return "validation_failed"
        
        # ✅ 所有轮次都成功，正常保存
        logs.append(f"✅ 验证成功: 所有轮次成功={valid_results_count}/3, 保存validation结果")
        
        # ⚠️ 保持reasoning阶段的原始result不变，不覆盖task.result
        # 原始reasoning结果: task.result (保持不变)
        # 只更新short_result用于筛选
        task.set_short_result(final_short_result)
        
        # 保存完整日志和验证结果到scan_record
        scan_data = {
            'logs': logs,
            'round_results': round_results,
            'process_time': process_time,
            'timestamp': datetime.utcnow().isoformat(),
            'rounds_count': 3,
            'validation_detailed_result': final_detailed_result,  # 验证阶段的详细结果
            'validation_short_result': final_short_result,        # 验证阶段的简短结果
            'original_reasoning_result': task.result              # 保存原始reasoning结果供参考
        }
        # 计算粗粒度资金风险分值（无fork情况下）
        try:
            from agentic.far_scoring import FundsAtRiskScorer
            far = FundsAtRiskScorer().score_from_confirmation(round_results, final_short_result)
            scan_data['funds_at_risk'] = far
        except Exception:
            scan_data['funds_at_risk'] = 0
        # 如果主流程已运行Orchestrator，可从scan_data['orchestrator']覆写更精确的FAR
        try:
            orch = scan_data.get('orchestrator', {})
            if isinstance(orch, dict) and isinstance(orch.get('funds_at_risk'), int):
                scan_data['funds_at_risk'] = orch['funds_at_risk']
        except Exception:
            pass
        task.scan_record = json.dumps(scan_data, ensure_ascii=False)
        
        # 更新数据库
        task_manager.save_task(task)
        
        return final_short_result
    
    def _execute_single_detection_round(self, vulnerability_result, business_flow_code, task, round_num, logs):
        """执行单轮检测流程"""
        from openai_api.openai import (perform_initial_vulnerability_validation,
                                       determine_additional_context_needed,
                                       perform_comprehensive_vulnerability_analysis)
        from prompt_factory.vul_check_prompt import VulCheckPrompt
        
        print(f"🔍 [Round {round_num}] 开始执行单轮检测流程")
        logs.append(f"第 {round_num} 轮: 开始初步确认")
        
        # 第一步：使用prompt factory生成完整的初步分析prompt，注入记忆上下文
        memory_snippets = []
        try:
            if self.agent_memory:
                recalled = self.agent_memory.recall("analysis_context", k=3)
                for r in recalled:
                    snippet = r.get("chunk_text") or r.get("natural_description") or ""
                    if snippet:
                        memory_snippets.append(snippet[:400])
        except Exception:
            pass

        memory_context = ("\n\n" + "\n---\n".join(memory_snippets)) if memory_snippets else ""

        initial_prompt = VulCheckPrompt.vul_check_prompt_agent_initial_complete(
            vulnerability_result + memory_context, business_flow_code
        )

        try:
            # 使用专门的初始分析模型获取自然语言响应
            natural_response = perform_initial_vulnerability_validation(initial_prompt)
            
            # 🔍 初始分析调试信息
            logs.append(f"第 {round_num} 轮: 初始分析响应类型={type(natural_response)}")
            logs.append(f"第 {round_num} 轮: 初始分析响应长度={len(str(natural_response)) if natural_response else 0}")
            logs.append(f"第 {round_num} 轮: 初始分析响应前200字符={repr(str(natural_response)[:200]) if natural_response else 'None'}")
            
            if not natural_response:
                logs.append(f"第 {round_num} 轮: 初始分析模型无响应")
                return "not_sure"
            
            logs.append(f"第 {round_num} 轮: 初始分析自然语言响应长度={len(natural_response)}")
            
            # 使用prompt factory生成JSON提取prompt
            json_extraction_prompt = VulCheckPrompt.vul_check_prompt_agent_json_extraction(
                natural_response
            )

            initial_response = extract_structured_json(json_extraction_prompt)
            
            # 🔍 详细调试信息
            logs.append(f"第 {round_num} 轮: JSON提取原始响应类型={type(initial_response)}")
            logs.append(f"第 {round_num} 轮: JSON提取原始响应长度={len(str(initial_response)) if initial_response else 0}")
            logs.append(f"第 {round_num} 轮: JSON提取原始响应前200字符={repr(str(initial_response)[:200]) if initial_response else 'None'}")
            
            if not initial_response:
                logs.append(f"第 {round_num} 轮: JSON提取失败 - 响应为空")
                return "not_sure"
            
            try:
                # 🔧 ask_openai_for_json 已经处理了JSON提取，直接解析
                initial_result = json.loads(initial_response) if isinstance(initial_response, str) else initial_response
                logs.append(f"第 {round_num} 轮: JSON解析成功，结果类型={type(initial_result)}")
            except json.JSONDecodeError as e:
                logs.append(f"第 {round_num} 轮: JSON解析失败 - {str(e)}")
                logs.append(f"第 {round_num} 轮: 原始内容={repr(initial_response)}")
                return "not_sure"
            assessment = initial_result.get('initial_assessment', 'not_sure')
            additional_info = initial_result.get('additional_info_needed', '')
            
            logs.append(f"第 {round_num} 轮: 初步评估={assessment}")
            logs.append(f"第 {round_num} 轮: 自然语言分析={natural_response[:200]}...")
            
            # 如果是明确的yes或no，直接返回
            if assessment in ['yes', 'no']:
                print(f"✅ [Round {round_num}] 获得明确结果: {assessment}")
                logs.append(f"第 {round_num} 轮: 明确结果，直接返回")
                # 🔧 特别是在遇到 'no' 时，直接退出不进行后续确认
                if assessment == 'no':
                    print(f"🚫 [Round {round_num}] 检测到 'no' 结果，跳过所有后续确认流程")
                    logs.append(f"第 {round_num} 轮: 检测到 'no' 结果，提前结束验证")
                return assessment
            
            # 如果需要更多信息，进入自循环（最多10轮）
            else:
                print(f"🔄 [Round {round_num}] 需要更多信息，进入内部循环")
                logs.append(f"第 {round_num} 轮: 需要更多信息: {additional_info}")
                
                # 进入自循环，最多10轮
                max_inner_rounds = 10
                current_assessment = assessment
                current_additional_info = additional_info
                accumulated_context = ""
                
                for inner_round in range(1, max_inner_rounds + 1):
                    logs.append(f"第 {round_num} 轮-内部第 {inner_round} 次: 开始获取额外信息")
                    
                    try:
                        # 获取所有类型的RAG信息
                        all_additional_info = self._get_all_additional_info(
                            current_additional_info, task, logs, round_num
                        )
                        
                        # 格式化为字符串
                        additional_context = self._format_all_additional_info(all_additional_info)
                        
                        # 累积上下文信息
                        if accumulated_context:
                            accumulated_context += f"\n\n=== 第{inner_round}轮额外信息 ===\n" + additional_context
                        else:
                            accumulated_context = additional_context
                        
                        logs.append(f"第 {round_num} 轮-内部第 {inner_round} 次: 获取RAG信息完成")
                            
                        # 使用prompt factory生成最终分析prompt
                        final_analysis_prompt = VulCheckPrompt.vul_check_prompt_agent_final_analysis(
                            vulnerability_result, business_flow_code, current_assessment, current_additional_info, accumulated_context
                        )
                        
                        # 使用专门的最终分析模型进行最终分析
                        final_natural_response = perform_comprehensive_vulnerability_analysis(final_analysis_prompt)
                        
                        # 🔍 最终分析调试信息
                        logs.append(f"第 {round_num} 轮-内部第 {inner_round} 次: 最终分析响应类型={type(final_natural_response)}")
                        logs.append(f"第 {round_num} 轮-内部第 {inner_round} 次: 最终分析响应长度={len(str(final_natural_response)) if final_natural_response else 0}")
                        
                        if not final_natural_response:
                            logs.append(f"第 {round_num} 轮-内部第 {inner_round} 次: 最终分析模型无响应")
                            continue
                        

                        
                        # 使用prompt factory生成最终结果提取prompt
                        final_extraction_prompt = VulCheckPrompt.vul_check_prompt_agent_final_extraction(
                            final_natural_response
                        )

                        final_response = extract_structured_json(final_extraction_prompt)
                        
                        # 🔍 最终结果提取调试信息
                        logs.append(f"第 {round_num} 轮-内部第 {inner_round} 次: 最终提取原始响应类型={type(final_response)}")
                        logs.append(f"第 {round_num} 轮-内部第 {inner_round} 次: 最终提取原始响应长度={len(str(final_response)) if final_response else 0}")
                        
                        if not final_response:
                            logs.append(f"第 {round_num} 轮-内部第 {inner_round} 次: 最终提取失败 - 响应为空")
                            continue
                        
                        try:
                            # 🔧 extract_structured_json 已经处理了JSON提取，直接解析
                            final_result = json.loads(final_response) if isinstance(final_response, str) else final_response
                            logs.append(f"第 {round_num} 轮-内部第 {inner_round} 次: 最终JSON解析成功，结果类型={type(final_result)}")
                            
                            final_assessment = final_result.get('final_result', 'not_sure')
                            final_additional_info = final_result.get('additional_info_needed', '')
                            
                            logs.append(f"第 {round_num} 轮-内部第 {inner_round} 次: 最终结果={final_assessment}")
                            logs.append(f"第 {round_num} 轮-内部第 {inner_round} 次: 最终分析={final_natural_response[:200]}...")
                            
                            # 如果得到明确的yes或no，退出循环
                            if final_assessment in ['yes', 'no']:
                                print(f"🎯 [Round {round_num}-{inner_round}] 内部循环获得明确结果: {final_assessment}")
                                logs.append(f"第 {round_num} 轮-内部第 {inner_round} 次: 得到明确结果，退出循环")
                                # 🔧 特别是在遇到 'no' 时，直接退出不进行后续确认
                                if final_assessment == 'no':
                                    print(f"🚫 [Round {round_num}-{inner_round}] 内部循环检测到 'no' 结果，跳过所有后续确认流程")
                                    logs.append(f"第 {round_num} 轮-内部第 {inner_round} 次: 检测到 'no' 结果，提前结束验证")
                                return final_assessment
                            
                            # 如果仍然是need_more_info，继续下一轮
                            else:
                                if inner_round < max_inner_rounds:
                                    logs.append(f"第 {round_num} 轮-内部第 {inner_round} 次: 仍需更多信息，继续下一轮")
                                    current_assessment = final_assessment
                                    current_additional_info = final_additional_info if final_additional_info else current_additional_info
                                    continue
                                else:
                                    logs.append(f"第 {round_num} 轮-内部第 {inner_round} 次: 达到最大循环次数，退出")
                                    return 'not_sure'
                                
                        except json.JSONDecodeError as e:
                            logs.append(f"第 {round_num} 轮-内部第 {inner_round} 次: 最终JSON解析失败 - {str(e)}")
                            logs.append(f"第 {round_num} 轮-内部第 {inner_round} 次: 最终原始内容={repr(final_response)}")
                            continue
                        
                    except Exception as e:
                        logs.append(f"第 {round_num} 轮-内部第 {inner_round} 次: 信息获取阶段失败: {str(e)}")
                        continue
                
                # 如果所有轮次都没有得到明确结果
                logs.append(f"第 {round_num} 轮: 所有内部循环完成，未得到明确结果")
                return 'not_sure'
            
            # 如果以上都失败，返回初步评估结果
            return assessment if assessment in ['yes', 'no'] else 'not_sure'
            
        except Exception as e:
            import traceback
            error_details = traceback.format_exc()
            print(f"❌ [Round {round_num}] 检测过程发生异常: {str(e)}")
            logs.append(f"第 {round_num} 轮: 检测失败: {str(e)}")
            logs.append(f"第 {round_num} 轮: 完整错误堆栈: {error_details}")
            return "not_sure"

   
    
    def _get_all_additional_info(self, specific_query, task, logs, round_num):
        """同时获取所有类型的RAG信息 - 使用并行处理优化性能"""
        from ..utils.parallel_utils import ParallelProcessor
        
        all_info = {
            'function_info': [],
            'file_info': [],
            'upstream_downstream_info': [],
            'chunk_info': []
        }
        
        try:
            # 🚀 并行执行RAG搜索和上下游分析
            parallel_tasks = []
            
            # 1. 并行执行RAG搜索 (Function + Chunk)
            if self.rag_processor:
                parallel_tasks.append({
                    'name': 'rag_searches',
                    'func': ParallelProcessor.execute_rag_searches_parallel,
                    'args': (self.rag_processor, specific_query),
                    'kwargs': {
                        'task': task,
                        'round_num': round_num,
                        'function_topk': 5,
                        'chunk_topk': 3,
                        'max_chunk_tokens': 150000
                    }
                })
            
            # 2. 并行执行上下游分析
            if hasattr(self, 'context_data') and self.context_data.get('project_audit'):
                parallel_tasks.append({
                    'name': 'upstream_downstream',
                    'func': self._get_upstream_downstream_with_levels,
                    'args': (task, 3, 4, logs, round_num)
                })
            
            # 执行并行任务
            if parallel_tasks:
                results = ParallelProcessor.execute_parallel_tasks(
                    parallel_tasks, 
                    max_workers=int(os.getenv("MAX_PARALLEL_RAG_WORKERS", 3))
                )
                
                # 处理RAG搜索结果
                rag_results = results.get('rag_searches')
                if rag_results:
                    # 处理函数搜索结果
                    function_results = rag_results.get('function_results', [])
                    for result in function_results:
                        func_name = result.get('name', 'Unknown')
                        func_content = result.get('content', '')
                        all_info['function_info'].append({
                            'name': func_name,
                            'content': func_content,
                            'type': 'function'
                        })
                    
                    # 处理chunk搜索结果
                    chunk_results = rag_results.get('chunk_results', [])
                    for result in chunk_results:
                        chunk_text = result.get('chunk_text', '')
                        original_file = result.get('original_file', 'Unknown')
                        all_info['chunk_info'].append({
                            'text': chunk_text,
                            'file': original_file,
                            'type': 'chunk'
                        })
                
                # 处理上下游分析结果
                upstream_downstream_results = results.get('upstream_downstream')
                if upstream_downstream_results:
                    all_info['upstream_downstream_info'] = upstream_downstream_results
            
            else:
                # 回退到串行处理（如果没有可并行的任务）
                print(f"  ⚠️ 第 {round_num} 轮: 无可并行任务，回退到串行处理")
                
                # 原有的串行逻辑作为备用
                if self.rag_processor:
                    try:
                        # 使用并行函数搜索
                        search_results = ParallelProcessor.execute_function_searches_parallel(
                            self.rag_processor, specific_query, 2
                        )
                        
                        function_results = self._merge_and_deduplicate_functions(
                            search_results['name_results'],
                            search_results['content_results'], 
                            search_results['natural_results'],
                            5
                        )
                        
                        for result in function_results:
                            func_name = result.get('name', 'Unknown')
                            func_content = result.get('content', '')
                            all_info['function_info'].append({
                                'name': func_name,
                                'content': func_content,
                                'type': 'function'
                            })
                            
                    except Exception as e:
                        print(f"  ❌ 第 {round_num} 轮: 并行函数搜索失败: {str(e)}")
                
                # 上下游分析
                try:
                    upstream_downstream_results = self._get_upstream_downstream_with_levels(task, 3, 4, logs, round_num)
                    all_info['upstream_downstream_info'] = upstream_downstream_results
                except Exception as e:
                    print(f"  ❌ 第 {round_num} 轮: 上下游分析失败: {str(e)}")
            
            # 5. 去重逻辑：从upstream/downstream中去除与function相同的
            all_info = self._remove_function_duplicates_from_upstream_downstream(all_info)
            
            return all_info
            
        except Exception as e:
            print(f"  ❌ 第 {round_num} 轮: 并行RAG处理失败，回退到基础模式: {str(e)}")
            return all_info
    
    def _merge_and_deduplicate_functions(self, name_results, content_results, natural_results, max_count):
        """合并和去重函数搜索结果（三种类型）"""
        seen_names = set()
        merged_results = []
        
        # 先加入按名称搜索的结果
        for result in name_results:
            func_name = result.get('name', '')
            if func_name and func_name not in seen_names:
                seen_names.add(func_name)
                merged_results.append(result)
                if len(merged_results) >= max_count:
                    break
        
        # 再加入按内容搜索的结果（去重）
        for result in content_results:
            func_name = result.get('name', '')
            if func_name and func_name not in seen_names:
                seen_names.add(func_name)
                merged_results.append(result)
                if len(merged_results) >= max_count:
                    break
        
        # 最后加入按自然语言搜索的结果（去重）
        for result in natural_results:
            func_name = result.get('name', '')
            if func_name and func_name not in seen_names:
                seen_names.add(func_name)
                merged_results.append(result)
                if len(merged_results) >= max_count:
                    break
        
        return merged_results[:max_count]
    
    def _get_upstream_downstream_with_levels(self, task, upstream_level, downstream_level, logs, round_num):
        """获取上下游信息（复用planning中的实现）- 使用并行处理优化性能"""
        from ..utils.parallel_utils import ParallelProcessor
        
        upstream_downstream = []
        
        # 获取project_audit实例
        project_audit = getattr(self, 'project_audit', None) or self.context_data.get('project_audit')
        if not project_audit:
            return upstream_downstream
        
        # 检查project_audit的call_trees属性
        has_call_trees = hasattr(project_audit, 'call_trees') and project_audit.call_trees
        if not has_call_trees:
            return upstream_downstream
        
        try:
            # 复用planning中的方法获取内容
            from planning.planning_processor import PlanningProcessor
            planning_processor = PlanningProcessor(project_audit, None)
            
            # 🚀 并行执行上游和下游内容获取
            parallel_results = ParallelProcessor.execute_upstream_downstream_parallel(
                planning_processor,
                task.name,
                upstream_level,
                downstream_level,
                self._get_upstream_content_with_call_tree
            )
            
            # 处理下游结果
            downstream_content = parallel_results.get('downstream_content')
            if downstream_content:
                upstream_downstream.append({
                    'content': downstream_content,
                    'type': 'downstream',
                    'level': downstream_level,
                    'count': downstream_content.count('\n\n') + 1
                })
            else:
                print(f"    ❌ 第 {round_num} 轮: downstream内容为空")
            
            # 处理上游结果
            upstream_content = parallel_results.get('upstream_content')
            if upstream_content:
                upstream_downstream.append({
                    'content': upstream_content,
                    'type': 'upstream',
                    'level': upstream_level,
                    'count': upstream_content.count('\n\n') + 1
                })
            else:
                print(f"    ❌ 第 {round_num} 轮: upstream内容为空")
            
        except Exception as e:
            import traceback
            error_details = traceback.format_exc()
            print(f"    ❌ 第 {round_num} 轮: 并行上下游分析失败: {str(e)}")
            # 回退到串行处理
            try:
                from planning.planning_processor import PlanningProcessor
                planning_processor = PlanningProcessor(project_audit, None)
                
                # 串行获取下游内容
                downstream_content = planning_processor.get_downstream_content_with_call_tree(
                    task.name, downstream_level
                )
                if downstream_content:
                    upstream_downstream.append({
                        'content': downstream_content,
                        'type': 'downstream',
                        'level': downstream_level,
                        'count': downstream_content.count('\n\n') + 1
                    })
                
                # 串行获取上游内容
                upstream_content = self._get_upstream_content_with_call_tree(
                    task.name, upstream_level, planning_processor
                )
                if upstream_content:
                    upstream_downstream.append({
                        'content': upstream_content,
                        'type': 'upstream',
                        'level': upstream_level,
                        'count': upstream_content.count('\n\n') + 1
                    })
                    
            except Exception as fallback_e:
                print(f"    ❌ 第 {round_num} 轮: 串行上下游分析也失败: {str(fallback_e)}")
        
        return upstream_downstream
    
    def _get_upstream_content_with_call_tree(self, func_name: str, max_depth: int, planning_processor) -> str:
        """获取upstream内容（使用统一的提取逻辑）"""
        try:
            # 使用planning_processor的统一upstream方法
            return planning_processor.get_upstream_content_with_call_tree(func_name, max_depth)
        except Exception as e:
            print(f"⚠️ 获取upstream内容失败: {e}")
            return ""
    
    def _remove_function_duplicates_from_upstream_downstream(self, all_info):
        """从upstream/downstream中去除与function相同的结果"""
        # 获取所有function名称
        function_names = set()
        for func_info in all_info['function_info']:
            function_names.add(func_info.get('name', ''))
        
        # 从upstream/downstream内容中移除包含相同functions的部分
        # 这里简化处理，主要是避免内容重复
        # 实际上，upstream/downstream和function的内容是不同的角度，可以保留
        
        return all_info
    
    def _format_all_additional_info(self, all_info):
        """格式化所有额外信息为字符串（完整版本，无省略）"""
        context_parts = []
        
        # Function信息
        if all_info['function_info']:
            context_parts.append("=== 相关函数 (Top 5) ===")
            for i, func in enumerate(all_info['function_info'], 1):
                context_parts.append(f"{i}. 函数: {func.get('name', 'Unknown')}")
                context_parts.append(f"   代码: {func.get('content', '')}\n")  # 🔧 移除截断和省略号
        
        # File信息 - 已注释
        # if all_info['file_info']:
        #     context_parts.append("=== 相关文件 (Top 2) ===")
        #     for i, file in enumerate(all_info['file_info'], 1):
        #         context_parts.append(f"{i}. 文件: {file.get('path', 'Unknown')}")
        #         context_parts.append(f"   内容: {file.get('content', '')}\n")  # 🔧 移除截断和省略号
        
        # Upstream/Downstream信息
        if all_info['upstream_downstream_info']:
            context_parts.append("=== 上下游关系信息 ===")
            for info in all_info['upstream_downstream_info']:
                level = info.get('level', 0)
                info_type = info.get('type', 'unknown')
                count = info.get('count', 0)
                context_parts.append(f"{info_type.title()}函数 (深度{level}, 共{count}个):")
                context_parts.append(f"{info.get('content', '')}\n")  # 🔧 移除截断和省略号
        
        # Chunk信息
        if all_info['chunk_info']:
            context_parts.append("=== 相关文档块 (Top 3) ===")
            for i, chunk in enumerate(all_info['chunk_info'], 1):
                context_parts.append(f"{i}. 文件: {chunk.get('file', 'Unknown')}")
                context_parts.append(f"   内容: {chunk.get('text', '')}\n")  # 🔧 移除截断和省略号
        
        return '\n'.join(context_parts) if context_parts else "未找到相关信息"

    def _aggregate_round_results(self, round_results, logs):
        """汇总三轮结果，生成最终判断"""
        logs.append("开始汇总三轮结果")
        
        # 🔧 特殊处理：如果第一轮就是 'no' 并且只有一轮结果，直接返回 'no'
        if len(round_results) == 1 and round_results[0] == 'no':
            logs.append("特殊情况: 第一轮即为 'no' 结果，提前退出验证")
            final_short_result = "no"
            decision_reason = "第一轮检测确认不存在漏洞，提前结束验证"
            detailed_result = f"""Agent化检测结果（提前退出）:
轮次结果: {round_results}
最终判断: {final_short_result}
决策依据: {decision_reason}
"""
            logs.append(f"最终汇总: {final_short_result} - {decision_reason}")
            return final_short_result, detailed_result
        
        # 统计各种结果
        yes_count = sum(1 for result in round_results if result == 'yes')
        no_count = sum(1 for result in round_results if result == 'no')
        not_sure_count = sum(1 for result in round_results if result == 'not_sure')
        
        logs.append(f"结果统计: yes={yes_count}, no={no_count}, not_sure={not_sure_count}")
        
        # 决策逻辑
        if yes_count >= 2:  # 至少2轮说yes
            final_short_result = "yes"
            decision_reason = f"3轮检测中{yes_count}轮确认存在漏洞"
        elif no_count >= 2:  # 至少2轮说no
            final_short_result = "no"
            decision_reason = f"3轮检测中{no_count}轮确认不存在漏洞"
        elif no_count >= 1:  # 🔧 改进：任何一轮说no，就倾向于no（特别是提前退出的情况）
            final_short_result = "no"
            decision_reason = f"检测中{no_count}轮确认不存在漏洞"
        else:  # 结果不一致或都是not_sure
            if yes_count > no_count:
                final_short_result = "yes"
                decision_reason = f"检测结果不一致，但{yes_count}轮倾向于存在漏洞"
            elif no_count > yes_count:
                final_short_result = "no"
                decision_reason = f"检测结果不一致，但{no_count}轮倾向于不存在漏洞"
            else:
                final_short_result = "not_sure"
                decision_reason = f"检测结果无法确定，需人工复核"
        
        # 生成详细结果
        detailed_result = f"""Agent化三轮检测结果:
轮次结果: {round_results}
统计: yes={yes_count}, no={no_count}, not_sure={not_sure_count}
最终判断: {final_short_result}
决策依据: {decision_reason}
"""
        
        logs.append(f"最终汇总: {final_short_result} - {decision_reason}")
        
        return final_short_result, detailed_result

    def _extract_function_names_from_tree(self, tree_data):
        """从调用树数据中提取函数名列表"""
        function_names = []
        
        try:
            if isinstance(tree_data, dict):
                for key, value in tree_data.items():
                    if isinstance(key, str) and '.' in key:  # 假设函数名格式为 ContractName.functionName
                        function_names.append(key)
                    elif isinstance(value, dict):
                        # 递归处理嵌套结构
                        nested_names = self._extract_function_names_from_tree(value)
                        function_names.extend(nested_names)
            elif isinstance(tree_data, list):
                for item in tree_data:
                    if isinstance(item, str) and '.' in item:
                        function_names.append(item)
                    elif isinstance(item, dict):
                        nested_names = self._extract_function_names_from_tree(item)
                        function_names.extend(nested_names)
        except Exception as e:
            pass
        
        return list(set(function_names))  # 去重

    def _extract_function_content_from_tree(self, tree_data):
        """从调用树数据中提取函数的实际代码内容"""
        function_contents = []
        
        try:
            if isinstance(tree_data, dict):
                for key, value in tree_data.items():
                    if isinstance(key, str) and '.' in key:  # 函数名格式为 ContractName.functionName
                        # 从self.functions中查找对应的函数内容
                        function_content = self._get_function_content_by_name(key)
                        if function_content:
                            function_contents.append(f"// {key}\n{function_content}")
                    
                    # 递归处理嵌套结构
                    if isinstance(value, dict):
                        nested_content = self._extract_function_content_from_tree(value)
                        if nested_content:
                            function_contents.append(nested_content)
            elif isinstance(tree_data, list):
                for item in tree_data:
                    if isinstance(item, str) and '.' in item:
                        function_content = self._get_function_content_by_name(item)
                        if function_content:
                            function_contents.append(f"// {item}\n{function_content}")
                    elif isinstance(item, dict):
                        nested_content = self._extract_function_content_from_tree(item)
                        if nested_content:
                            function_contents.append(nested_content)
        except Exception as e:
            pass
        
        return '\n\n'.join(function_contents) if function_contents else ""

    def _get_function_content_by_name(self, function_name):
        """根据函数名从self.functions中获取函数内容"""
        try:
            for func in self.functions:
                if isinstance(func, dict) and func.get('name') == function_name:
                    return func.get('content', '')
            return ""
        except Exception as e:
            return "" 