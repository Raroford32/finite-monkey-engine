"""
假设验证相关的提示词工厂
用于在reasoning阶段验证代码假设是否成立
"""

class AssumptionValidationPrompt:
    """假设验证提示词类"""
    
    @staticmethod
    def get_assumption_validation_prompt(code: str, assumption_statement) -> str:
        """获取假设验证的提示词
        
        Args:
            code: 要分析的代码
            assumption_statement: 需要验证的假设陈述（可以是字符串或列表）
            
        Returns:
            str: 完整的假设验证提示词
        """
        # 支持单个或多个assumption/invariant
        if isinstance(assumption_statement, list):
            statements_text = "\n\n".join([f"{i+1}. {stmt}" for i, stmt in enumerate(assumption_statement)])
            instruction = "Analyze the following code to validate whether each of the stated assumptions/invariants is correct or represents a security vulnerability."
        else:
            statements_text = assumption_statement
            instruction = "Analyze the following code to validate whether the stated assumption/invariant is correct or represents a security vulnerability."
        
        return f"""
You are an expert smart contract security auditor. {instruction}

ASSUMPTIONS/INVARIANTS TO VALIDATE:
{statements_text}

CODE TO ANALYZE:
{code}

For each assumption/invariant, determine if it is CORRECT, INCORRECT, or PARTIALLY CORRECT based on the code analysis. Focus on potential security risks, missing safeguards, and attack vectors. Provide specific evidence from the code and actionable recommendations.

Begin your analysis now.
"""