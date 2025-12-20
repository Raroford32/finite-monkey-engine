"""
Economic Attack Methodology Prompts

Based on the "Autonomous Vulnerability Discovery: First-Principles Methodology"
This module provides specialized prompts for discovering system-level economic attacks
rather than simple code-level bugs.

Core Philosophy: Every exploit is a violation of an economic assumption.
We don't search for known patterns—we discover what assumptions a system makes,
then determine which can be violated.
"""


class EconomicAttackPrompt:
    """Economic attack analysis prompt class."""

    @staticmethod
    def get_economic_system_decomposition_prompt(code: str) -> str:
        """Get prompt for Phase 1: Economic System Decomposition.
        
        Args:
            code: The code to analyze
            
        Returns:
            str: Complete economic system analysis prompt
        """
        return f"""
You are an expert DeFi security researcher. Your task is to decompose this protocol
as an ECONOMIC MACHINE, not just code.

PHASE 1: ECONOMIC SYSTEM DECOMPOSITION

1. VALUE INVENTORY - Map where value exists:
   - What assets can this protocol hold? (tokens, ETH, positions, LP shares, collateral)
   - Where does value accumulate? (pools, vaults, treasuries, user balances, unclaimed rewards)
   - What represents claims on value? (shares, receipts, position NFTs, accounting entries)
   - What is the relationship between claims and underlying? (the conversion math)

2. VALUE FLOW ANALYSIS - Trace how value moves:
   For each value flow (deposits, withdrawals, swaps, liquidations, rewards):
   - Who can initiate it? (user, keeper, anyone, admin)
   - What determines the amount? (input params, oracle, internal state, calculation)
   - What state changes occur? (balances, positions, global accumulators)
   - What external calls happen? (other contracts, oracles, callbacks)

3. ASSUMPTION EXTRACTION - Extract implicit assumptions:

   Temporal Assumptions:
   - "State A will always be true when action B occurs"
   - "X happens before Y in every valid sequence"
   - "This value won't change during execution"

   Trust Assumptions:
   - "Only authorized parties can call this"
   - "External contracts behave as expected"
   - "Users won't take economically irrational actions"

   Mathematical Assumptions:
   - "This calculation won't overflow/underflow"
   - "Rounding errors are insignificant"
   - "These values maintain this invariant"

   State Assumptions:
   - "This mapping always has an entry when accessed"
   - "These two values are always synchronized"
   - "This can never be zero when used as divisor"

CODE TO ANALYZE:
{code}

OUTPUT FORMAT:
Provide a structured analysis with:
1. Value Inventory (where money lives)
2. Value Flows (how money moves)
3. Critical Assumptions (what could break)
4. Economic Game Players (who interacts and what do they want)
5. External Dependencies (oracles, other protocols, keepers)

Focus on ECONOMIC MECHANICS, not code bugs.
"""

    @staticmethod
    def get_extraction_path_discovery_prompt(code: str) -> str:
        """Get prompt for Phase 2: Extraction Path Discovery.
        
        Args:
            code: The code to analyze
            
        Returns:
            str: Complete extraction path analysis prompt
        """
        return f"""
You are an expert DeFi attacker (for research purposes). Your goal is to find ways
to extract value from this protocol in ways the designers didn't intend.

PHASE 2: EXTRACTION PATH DISCOVERY

THE FUNDAMENTAL QUESTION:
"How do I get more out than I'm entitled to, or get the same out while putting less in?"

This manifests as:

1. CLAIM INFLATION - Make the system think I own more than I do:
   - Can I deposit X but get recorded as X+Y?
   - Can I manipulate share:asset ratio before my action?
   - Can I inflate my recorded balance without real deposit?

2. COST REDUCTION - Pay less than I should:
   - Can I borrow X but record debt as X-Y?
   - Can I repay with manipulated token/price?
   - Can I extract before fees/interest are applied?

3. DEFLATE OTHERS' CLAIMS - Take from other users:
   - Can I reduce what others can withdraw?
   - Can I cause their positions to be liquidated unfairly?
   - Can I front-run their operations profitably?

4. BYPASS PAYMENT - Get value without paying:
   - Can I mint claims without deposits?
   - Can I claim rewards I didn't earn?
   - Can I receive liquidation bonus without valid liquidation?

5. VALUE REDIRECTION - Redirect money flow:
   - Can another user's withdrawal credit my account?
   - Can protocol fees route to me instead of treasury?
   - Can I become recipient of misrouted funds?

6. GRIEFING FOR PROFIT - Cause losses that benefit me:
   - Can I force others into unfavorable liquidation?
   - Can I block withdrawals while shorting the token?
   - Can I manipulate state to devalue others' positions?

CODE TO ANALYZE:
{code}

For each extraction type above, analyze:
1. Is there a code path that could enable this?
2. What preconditions are required?
3. What is the estimated profit potential?
4. What capital is required (flash loans available?)
5. What prevents this attack currently?

OUTPUT: List concrete extraction paths with:
- Attack type
- Step-by-step execution
- Required capital
- Expected profit
- Current defenses (if any)
- Why this might be exploitable
"""

    @staticmethod
    def get_composition_attack_prompt(code: str, external_protocols: str = "") -> str:
        """Get prompt for compositional/cross-protocol attack analysis.
        
        Args:
            code: The code to analyze
            external_protocols: Description of external protocols this code interacts with
            
        Returns:
            str: Complete composition attack analysis prompt
        """
        external_context = f"\nKNOWN EXTERNAL INTEGRATIONS:\n{external_protocols}\n" if external_protocols else ""
        
        return f"""
You are an expert in DeFi composability attacks. Single-contract bugs are nearly extinct.
The exploits that remain are EMERGENT FROM COMPOSITION.

PHASE 3: COMPOSITIONAL ANALYSIS

The bug exists in NEITHER contract alone. It exists in the ASSUMPTION Contract A makes about Contract B.

COMPOSITION TYPES TO ANALYZE:

1. PROTOCOL ↔ PROTOCOL:
   - What does this code ASSUME about external protocols?
   - Can you make external protocols behave unexpectedly?
   - What if you're a user of BOTH protocols simultaneously?
   - Can you manipulate external state then immediately call this?

2. CONTRACT ↔ CONTRACT (within same protocol):
   - What state does Contract A assume is true after Contract B returns?
   - Can Contract B return "successfully" while leaving state inconsistent?
   - If you're called back during B execution, what's the state?
   - Are there re-entry points between contracts that bypass checks?

3. TRANSACTION ↔ TRANSACTION:
   - Setup TX → [something happens] → Extraction TX
   - What can happen between your transactions?
   - Can you control what happens (MEV, being your own keeper)?
   - What state persists between transactions?
   - Can you be both "victim" and "attacker" in protocol's logic?

4. USER ↔ USER (Economic Composition):
   - Can your actions affect other users' positions?
   - Can you profit from others' forced liquidations?
   - If you're the ONLY user, what degeneracies appear?
   - If you're EVERY user (multiple addresses), what's possible?

CROSS-PROTOCOL ATTACK PATTERNS:

A. FLASH LOAN LEVERAGE:
   - What assumptions break when someone has unlimited temporary capital?
   - Can state be manipulated and restored within single transaction?

B. ORACLE MANIPULATION VIA DEX:
   - Protocol uses DEX price → Can you move DEX price?
   - What's the TWAP window? Can you control enough blocks?
   
C. LIQUIDATION GAMING:
   - Can you manipulate conditions to make positions "underwater"?
   - Can you profit from liquidating yourself or others?
   
D. GOVERNANCE/TIMELOCK RACING:
   - Can you set up state exploitable AFTER governance executes?
   - Can you exploit BEFORE queued actions execute?
{external_context}
CODE TO ANALYZE:
{code}

For every external call or integration, answer:
1. What does this code ASSUME about the external system?
2. Can you VIOLATE that assumption?
3. If violated, what happens? Can you extract value?

OUTPUT: Concrete composition attacks with:
- Which protocols/contracts are composed
- What assumption is violated
- Attack sequence across contracts/transactions
- Estimated profit and required capital
"""

    @staticmethod
    def get_boundary_attack_prompt(code: str) -> str:
        """Get prompt for boundary and edge case analysis.
        
        Args:
            code: The code to analyze
            
        Returns:
            str: Complete boundary analysis prompt
        """
        return f"""
You are an expert at finding edge case exploits. Push the system to its LIMITS.

PHASE 4: BOUNDARY AND EDGE CASE ANALYSIS

Test at these boundaries:

| Parameter Type | Edge Cases to Test |
|----------------|-------------------|
| Amounts | 0, 1, 2, type(uint256).max, dust amounts |
| Timing | First block, after long pause, rapid succession |
| State | Empty pools, near-empty, exactly full |
| Users | First user, only user, many addresses same owner |
| Prices | 0, 1:1, extreme ratios, negative (if signed), max |
| Arrays | Empty, single element, maximum length |
| Percentages | 0%, 100%, >100%, fractional |

SPECIFIC BOUNDARY ATTACKS:

1. FIRST DEPOSITOR ATTACKS:
   - What happens when totalShares = 0 or very low?
   - Can share price be manipulated by first deposit?
   - Is there minimum deposit protection?

2. DONATION ATTACKS:
   - What if tokens are sent directly (not through deposit)?
   - Does balanceOf() vs internal accounting create gaps?

3. ROUNDING EXPLOITATION:
   - Where does rounding occur?
   - Does rounding favor protocol or user?
   - Can dust amounts accumulate to significant value?

4. ZERO VALUE EDGE CASES:
   - What happens with 0 amount transfers/swaps/stakes?
   - Are there division by zero possibilities?
   - What if price is 0?

5. MAXIMUM VALUE ATTACKS:
   - What happens at uint256.max?
   - Can overflow/underflow be triggered?
   - What if accumulated values approach max?

6. EMPTY STATE EXPLOITATION:
   - What if pool/vault is empty?
   - What if no other users exist?
   - What if all positions are closed?

7. TIMING BOUNDARIES:
   - What happens at epoch/period transitions?
   - What if block.timestamp is near deadline?
   - What if operations happen same block?

CODE TO ANALYZE:
{code}

For each boundary condition:
1. Can an attacker reach this state?
2. What is the unexpected behavior?
3. Can value be extracted from the unexpected behavior?
4. What is the attack sequence?

OUTPUT: Concrete boundary attacks with specific values that trigger exploits.
"""

    @staticmethod
    def get_multi_transaction_attack_prompt(code: str) -> str:
        """Get prompt for multi-transaction attack analysis.
        
        Args:
            code: The code to analyze
            
        Returns:
            str: Complete multi-transaction attack analysis prompt
        """
        return f"""
You are an expert in multi-step DeFi attacks. Real exploits span MULTIPLE TRANSACTIONS.

PHASE 5: MULTI-TRANSACTION ATTACK ANALYSIS

Pattern: Setup TX → [State Change / Time Passes] → Extraction TX

ATTACK PATTERNS:

1. SETUP-EXTRACTION PATTERN:
   - TX1: Establish favorable position
   - [Wait for oracle update / interest accrual / epoch change]
   - TX2: Extract value based on changed state
   - What positions can be "armed" to profit from future state?

2. MEV EXTRACTION:
   - What transactions can be profitably front-run?
   - What transactions can be profitably back-run?
   - What sandwich attacks are possible?
   - Can you profit from transaction ordering control?

3. ORACLE TIMING ATTACKS:
   - What happens between oracle updates?
   - Can you act on stale oracle data?
   - Can you manipulate then wait for TWAP to update?

4. GOVERNANCE EXPLOITATION:
   - What state can be setup before governance executes?
   - Can queued governance changes be exploited?
   - Can you vote then extract before vote settles?

5. INTEREST/REWARD TIMING:
   - When does interest accrue?
   - Can you deposit just before rewards, withdraw just after?
   - What happens at reward distribution boundaries?

6. POSITION BUILDING:
   - Can you gradually build a position undetected?
   - At what size does your position affect protocol behavior?
   - Can accumulated small positions trigger cascade effects?

7. SEQUENTIAL OPERATIONS:
   - Can rapid successive operations exploit timing gaps?
   - What happens with many operations in same block?
   - Can loop/batch operations be exploited?

CODE TO ANALYZE:
{code}

Analyze:
1. What STATE persists between transactions that you can manipulate?
2. What TIME-DEPENDENT changes occur that you can exploit?
3. What ORDERING of transactions maximizes extraction?
4. What ACCUMULATION effects can you exploit over time?

OUTPUT: Multi-step attack sequences with:
- Transaction sequence
- Required timing/ordering
- State manipulation at each step
- Expected profit
- Required blocks/time between steps
"""

    @staticmethod
    def get_hypothesis_testing_prompt(code: str, hypothesis: str) -> str:
        """Get prompt for testing a specific attack hypothesis.
        
        Args:
            code: The code to analyze
            hypothesis: The specific attack hypothesis to test
            
        Returns:
            str: Complete hypothesis testing prompt
        """
        return f"""
You are testing a SPECIFIC attack hypothesis. Your job is to either:
1. PROVE the attack works with concrete steps, OR
2. PROVE the attack is blocked with specific defenses

HYPOTHESIS TO TEST:
{hypothesis}

CODE TO ANALYZE:
{code}

TESTING METHODOLOGY:

1. STATE THE INVARIANT that would be violated:
   - What property SHOULD hold that this attack would break?
   - Express mathematically if possible

2. DESIGN THE MINIMAL ATTACK:
   - What is the simplest sequence that would violate this?
   - What initial state is required?
   - What specific function calls with what parameters?

3. CHECK FEASIBILITY:
   - Is this sequence actually executable? (permissions, ordering)
   - Is it economically profitable after gas?
   - Are there guards that prevent it?

4. IDENTIFY BLOCKERS:
   - What specific code prevents this attack?
   - Is the blocker sufficient? Could it be bypassed?
   - Are there alternative paths around the blocker?

5. ECONOMIC ANALYSIS:
   - If exploitable, what's the maximum extractable value?
   - What capital is required?
   - What's the risk/reward ratio?

VERDICT FORMAT:

If EXPLOITABLE:
```
VERDICT: EXPLOITABLE

Attack Steps:
1. [Specific function call with params]
2. [Next step...]
3. [Extraction step...]

Required Capital: [amount and token]
Expected Profit: [amount]
Prerequisites: [any required state/positions]
Current Defenses: [what could stop this, if anything]
Confidence: [HIGH/MEDIUM/LOW with reasoning]
```

If NOT EXPLOITABLE:
```
VERDICT: NOT EXPLOITABLE

Blocking Defense: [specific code/mechanism]
Defense Strength: [why it's sufficient]
Attempted Bypasses: [what was tried and why it failed]
Residual Risk: [any remaining concerns]
Confidence: [HIGH/MEDIUM/LOW with reasoning]
```
"""

    @staticmethod
    def get_economic_mindset_prompt() -> str:
        """Get the economic attacker mindset prompt to prepend to analyses.
        
        Returns:
            str: Economic mindset prompt
        """
        return """
ECONOMIC ATTACKER MINDSET

Before analyzing code, think like a $10M bounty hunter:

1. AUTOMATED TOOLS ALREADY RAN - Don't look for:
   - Basic reentrancy (ReentrancyGuard exists)
   - Integer overflow (Solidity 0.8+)
   - Access control on admin functions
   - Unchecked return values
   - tx.origin authentication
   
2. REAL EXPLOITS ARE ECONOMIC - Look for:
   - Multi-contract interaction bugs
   - Multi-transaction attack sequences
   - Cross-protocol composition attacks
   - Economic game theory violations
   - State machine assumption violations
   - Oracle/price manipulation paths
   - Timing/ordering exploitation

3. THE RIGHT QUESTIONS:
   - "What would a $10M exploit look like here?"
   - "What do automated tools NOT catch?"
   - "What assumptions span multiple contracts/transactions?"
   - "What happens at the boundaries of this system?"
   - "What would developers never think to test?"

4. MINIMUM COMPLEXITY THRESHOLD:
   If your hypothesis can be checked by Slither in <1 second, SKIP IT.
   Focus on attacks requiring:
   - Multi-contract state understanding
   - Economic reasoning about incentives
   - Sequences of 3+ operations
   - Understanding of "in between" transaction state
   - Knowledge of how external systems affect this protocol

5. EXPLAIN WHY SLITHER/MYTHRIL WOULD MISS THIS BUG
   If you can't explain why static analyzers miss it, it's not worth pursuing.
"""
