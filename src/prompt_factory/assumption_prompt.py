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

CRITICAL: Focus on SYSTEM-LEVEL ECONOMIC ASSUMPTIONS, not simple code bugs.
Real exploits are economic attacks where the code works as written but economic assumptions are violated.

For each assumption or invariant you identify, provide a comprehensive analysis that integrates ALL the following information into ONE complete statement:

- Detailed description of the specific business scenario
- Description of the business object targeted by the assumption/invariant
- Content of the assumption/invariant and expectation made by the developer
- Dependency conditions that must be met for this to hold true
- Corresponding code snippet that reflects this assumption/invariant
- ECONOMIC IMPACT: What value could be extracted if this assumption is violated?

Please ensure your analysis covers:

1. ECONOMIC ASSUMPTIONS - How value flows and can be manipulated:
- Value flow assumptions: Where does value enter, accumulate, and exit the system?
- Share/Asset ratio assumptions: How are claims on value calculated and could they be manipulated?
- Fee and reward assumptions: How are fees collected and rewards distributed?
- Liquidation assumptions: What conditions trigger liquidations and who benefits?
- Oracle/price assumptions: What external price data is trusted and could it be manipulated?
- Flash loan assumptions: What changes if an attacker has unlimited temporary capital?
- Multi-transaction assumptions: What if actions span multiple blocks/transactions?

2. CROSS-CONTRACT/PROTOCOL ASSUMPTIONS:
- External contract behavior: What does this code assume about how other contracts behave?
- Callback safety: What state is assumed to be stable during external calls?
- Re-entrancy assumptions: What operations could be interleaved through callbacks?
- Cross-protocol composition: What breaks if this is composed with flash loans, DEXes, or other DeFi?
- State synchronization: Are there assumptions about when external state updates?

3. STATE MACHINE AND TEMPORAL ASSUMPTIONS:
- State transition ordering: What sequence of states is assumed?
- Timing assumptions: What time-based constraints could be bypassed?
- Finality assumptions: What assumptions about transaction finality exist?
- Multi-block attack surface: What if an attacker controls multiple consecutive blocks?

4. BOUNDARY AND EDGE CASE ASSUMPTIONS:
- Zero value handling: What happens when amounts are exactly zero?
- First user assumptions: What if the attacker is the first or only user?
- Empty state assumptions: What if pools, vaults, or mappings are empty?
- Extreme value assumptions: What happens at uint256.max or other boundaries?
- Rounding assumptions: How do rounding errors accumulate?

5. TRADITIONAL CODE ASSUMPTIONS (lower priority but still relevant):
- Business logic assumptions: Assumptions about business processes, rules, and constraints
- Data structure assumptions: Assumptions about data storage, indexing, and relationships  
- Security assumptions: Assumptions about permission controls, attack prevention, and asset security
- User behavior assumptions: Assumptions about user operation patterns and interaction methods

6. EXPLICIT INVARIANTS - Properties that are explicitly enforced or checked in the code:
- Mathematical invariants: Properties like x >= y, total supply conservation, balance constraints
- State invariants: Properties that must hold before/after function execution
- Access control invariants: Permission and role-based properties
- Protocol invariants: Properties required by standards (e.g., ERC20, ERC721)

7. IMPLICIT INVARIANTS - Properties that are implicitly assumed but not explicitly checked:
- Unchained properties: Properties that should hold but lack validation
- Temporal invariants: Properties about state transitions over time
- Inter-contract invariants: Properties about relationships between contracts
- Economic invariants: Properties about value conservation, pricing, etc.

IMPORTANT OUTPUT FORMAT:
- Write each complete assumption/invariant as a single comprehensive paragraph in natural language
- Clearly label each item with [ECONOMIC_ASSUMPTION], [CROSS_PROTOCOL_ASSUMPTION], [TEMPORAL_ASSUMPTION], [BOUNDARY_ASSUMPTION], [ASSUMPTION], [EXPLICIT_INVARIANT], or [IMPLICIT_INVARIANT] at the beginning
- Separate each item using exactly "<|ASSUMPTION_SPLIT|>"  
- Do NOT use any JSON format, bullet points, or numbered lists
- Each item should be self-contained and include all relevant dimensions
- Start directly with the first item, no introductory text
- Prioritize economic and cross-protocol assumptions as these lead to the highest-impact vulnerabilities

Example format:
[ECONOMIC_ASSUMPTION] This code assumes that the share:asset ratio cannot be manipulated between deposit and withdrawal operations, which involves the economic scenario where an attacker could donate tokens directly to the vault to inflate the share price, causing subsequent depositors to receive fewer shares than expected, with the economic impact that the attacker could extract value from other users by controlling the timing of deposits and withdrawals, as evidenced by the direct use of balanceOf(address(this)) in the conversion calculation without protection against donation attacks.
<|ASSUMPTION_SPLIT|>
[CROSS_PROTOCOL_ASSUMPTION] This code assumes that external oracle prices are accurate at the time of use, but in a flash loan scenario an attacker could manipulate DEX prices that feed the oracle, trigger a liquidation at the manipulated price, then restore the price, extracting value from the liquidation bonus while the underlying position was actually healthy, as shown in the direct reliance on oracle.getPrice() without TWAP or multi-source validation.
<|ASSUMPTION_SPLIT|>
[TEMPORAL_ASSUMPTION] This code assumes that state transitions follow the sequence initialized -> active -> finalized, but there is no explicit check preventing a direct transition from initialized to finalized, which could allow an attacker to bypass the active period where normal operations should occur, as evidenced by the lack of state validation in the finalize() function.

Code to analyze:
{downstream_content}
"""

