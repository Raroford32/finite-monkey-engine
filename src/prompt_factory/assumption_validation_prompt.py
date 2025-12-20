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
You are an expert smart contract security auditor specializing in ECONOMIC ATTACKS and SYSTEM-LEVEL VULNERABILITIES.

CRITICAL MINDSET: Think like an attacker trying to extract $10M+. Do NOT focus on simple code bugs that static analyzers catch.
Real exploits are ECONOMIC violations where code works as written but assumptions about value flow are broken.

{instruction}

ASSUMPTIONS/INVARIANTS TO VALIDATE:
{statements_text}

CODE TO ANALYZE:
{code}

For each assumption/invariant, perform the following analysis:

1. ECONOMIC ATTACK VECTOR ANALYSIS:
   - What VALUE could be extracted if this assumption is violated?
   - Is there a PROFITABLE attack path? (Consider: flash loans, MEV, multi-tx attacks)
   - What's the minimum capital required vs potential profit?
   - Would this attack be economically viable after gas costs?

2. CROSS-PROTOCOL COMPOSITION CHECK:
   - What if this code is called via flash loan?
   - What if an attacker controls multiple contracts/positions?
   - What external protocols could be used to violate this assumption?
   - What if transaction ordering is controlled (MEV)?

3. STATE MANIPULATION ANALYSIS:
   - Can an attacker reach the required pre-conditions?
   - Can state be manipulated between key operations?
   - What happens at system boundaries (empty pools, first user, max values)?
   - Can timing/ordering be exploited?

4. MULTI-STEP ATTACK CONSTRUCTION:
   - If the assumption can be violated, construct a concrete attack:
     a) Setup transaction(s) - establish required state
     b) Trigger transaction - execute the exploit
     c) Extraction - how value is captured
   - Include specific function calls and approximate values

5. VERDICT:
   - CORRECT: The assumption holds and cannot be economically exploited
   - INCORRECT: The assumption can be violated AND there's a profitable attack path
   - PARTIALLY CORRECT: The assumption can be violated but attack is not economically viable
   - Provide SPECIFIC code evidence for your conclusion

IMPORTANT: 
- DO NOT flag theoretical issues without economic impact
- DO NOT flag issues requiring impractical capital (e.g., controlling majority of liquidity without flash loans, multi-year attack timelines)
- DO consider that flash loans enable temporary large positions - factor this into feasibility analysis
- DO focus on attacks that could realistically occur and extract significant value
- Provide concrete attack scenarios, not abstract vulnerability descriptions

Begin your analysis now.
"""