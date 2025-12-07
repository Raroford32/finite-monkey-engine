"""
假设分析相关的提示词工厂
"""

class AssumptionPrompt:
    """假设分析提示词类"""
    
    @staticmethod
    def get_assumption_analysis_prompt(downstream_content: str) -> str:
        """获取假设分析的提示词
        
        Args:
            downstream_content: 下游代码内容
            
        Returns:
            str: 完整的假设分析提示词
        """
        return f"""
Analyze in depth all business logic-related assumptions and invariants in this code.

For each assumption or invariant you identify, provide a comprehensive analysis that integrates ALL the following information into ONE complete statement:

- Detailed description of the specific business scenario
- Description of the business object targeted by the assumption/invariant
- Content of the assumption/invariant and expectation made by the developer
- Dependency conditions that must be met for this to hold true
- Corresponding code snippet that reflects this assumption/invariant

Please ensure your analysis covers:

1. DEVELOPER ASSUMPTIONS - All implicit assumptions in the following dimensions:
- Business logic assumptions: Assumptions about business processes, rules, and constraints
- Data structure assumptions: Assumptions about data storage, indexing, and relationships  
- Security assumptions: Assumptions about permission controls, attack prevention, and asset security
- User behavior assumptions: Assumptions about user operation patterns and interaction methods
- System architecture assumptions: Assumptions about technical implementation, scalability, and compatibility
- Economic model assumptions: Assumptions about tokenomics, incentive mechanisms, and value flow
- Integration assumptions: Assumptions about external systems, third-party services, and cross-chain interactions

2. EXPLICIT INVARIANTS - Properties that are explicitly enforced or checked in the code:
- Mathematical invariants: Properties like x >= y, total supply conservation, balance constraints
- State invariants: Properties that must hold before/after function execution
- Access control invariants: Permission and role-based properties
- Protocol invariants: Properties required by standards (e.g., ERC20, ERC721)

3. IMPLICIT INVARIANTS - Properties that are implicitly assumed but not explicitly checked:
- Unchained properties: Properties that should hold but lack validation
- Temporal invariants: Properties about state transitions over time
- Inter-contract invariants: Properties about relationships between contracts
- Economic invariants: Properties about value conservation, pricing, etc.

IMPORTANT OUTPUT FORMAT:
- Write each complete assumption/invariant as a single comprehensive paragraph in natural language
- Clearly label each item with [ASSUMPTION], [EXPLICIT_INVARIANT], or [IMPLICIT_INVARIANT] at the beginning
- Separate each item using exactly "<|ASSUMPTION_SPLIT|>"  
- Do NOT use any JSON format, bullet points, or numbered lists
- Each item should be self-contained and include all relevant dimensions
- Start directly with the first item, no introductory text

Example format:
[ASSUMPTION] This code assumes that users will always have sufficient balance before attempting a transfer, which involves the business scenario of token transfers between accounts where the balance tracking system accurately reflects user holdings, and the security assumption that msg.sender authentication prevents unauthorized access, with the dependency that the ERC20 standard's balance mapping is consistently maintained across all operations as shown in the require(balanceOf[msg.sender] >= amount) check.
<|ASSUMPTION_SPLIT|>
[EXPLICIT_INVARIANT] This code enforces that the total supply must never exceed the maximum cap through the require(totalSupply + amount <= MAX_SUPPLY) check, which maintains the mathematical invariant that prevents inflation beyond the predefined limit, ensuring the economic model remains sound and token scarcity is preserved as intended by the protocol design.
<|ASSUMPTION_SPLIT|>
[IMPLICIT_INVARIANT] This code implicitly relies on the invariant that the sum of all user balances equals the total supply, but this property is not explicitly verified after transfers or mints, creating a potential vulnerability where rounding errors or external manipulations could break this accounting invariant, as evidenced by the lack of validation in the _mint and _burn functions.

Code to analyze:
{downstream_content}
"""

