"""
Protocol Semantics Understanding Engine

This module provides deep semantic understanding of DeFi protocols
to discover novel logic exploits through formal modeling and analysis.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import networkx as nx
import z3

logger = logging.getLogger(__name__)


class ProtocolPrimitive(Enum):
    """Common DeFi protocol primitives"""
    LENDING = "lending"
    BORROWING = "borrowing"
    SWAPPING = "swapping"
    LIQUIDITY_PROVISION = "liquidity_provision"
    STAKING = "staking"
    GOVERNANCE = "governance"
    ORACLE = "oracle"
    FLASH_LOAN = "flash_loan"
    COLLATERAL = "collateral"
    LIQUIDATION = "liquidation"
    YIELD_FARMING = "yield_farming"
    VESTING = "vesting"
    AUCTION = "auction"
    BRIDGE = "bridge"
    SYNTHETIC = "synthetic"


@dataclass
class ProtocolState:
    """Represents protocol state at a point in time"""
    timestamp: int
    block_number: int
    
    # Token balances
    token_balances: Dict[str, Dict[str, float]] = field(default_factory=dict)
    
    # Pool states
    pool_reserves: Dict[str, Tuple[float, float]] = field(default_factory=dict)
    pool_total_supply: Dict[str, float] = field(default_factory=dict)
    
    # Lending states
    total_borrowed: Dict[str, float] = field(default_factory=dict)
    total_supplied: Dict[str, float] = field(default_factory=dict)
    utilization_rates: Dict[str, float] = field(default_factory=dict)
    
    # Price states
    prices: Dict[str, float] = field(default_factory=dict)
    oracle_prices: Dict[str, float] = field(default_factory=dict)
    
    # Governance states
    proposals: List[Dict[str, Any]] = field(default_factory=list)
    voting_power: Dict[str, float] = field(default_factory=dict)
    
    # Protocol parameters
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProtocolInvariant:
    """Represents a protocol invariant that must hold"""
    id: str
    name: str
    description: str
    formula: str  # Z3 formula or logical expression
    
    # Invariant properties
    scope: str  # global, pool, user, governance
    criticality: str  # critical, high, medium, low
    
    # Validation
    holds: bool = True
    violations: List[Dict[str, Any]] = field(default_factory=list)
    
    # Dependencies
    depends_on: List[str] = field(default_factory=list)
    affects: List[str] = field(default_factory=list)


@dataclass
class ProtocolAction:
    """Represents an action that can be taken in the protocol"""
    id: str
    name: str
    primitive: ProtocolPrimitive
    
    # Action properties
    actor: str
    target: str
    parameters: Dict[str, Any]
    
    # Requirements
    preconditions: List[str] = field(default_factory=list)
    postconditions: List[str] = field(default_factory=list)
    
    # Effects
    state_changes: Dict[str, Any] = field(default_factory=dict)
    side_effects: List[str] = field(default_factory=list)
    
    # Costs and risks
    gas_cost: int = 0
    capital_required: float = 0.0
    risk_score: float = 0.0


class ProtocolSemanticsEngine:
    """
    Deep semantic understanding of DeFi protocols for novel exploit discovery
    
    This engine models protocol behavior formally to discover logic exploits
    through invariant analysis, state space exploration, and compositional attacks.
    """
    
    def __init__(self):
        """Initialize the protocol semantics engine"""
        self.protocol_model = None
        self.state_space = nx.DiGraph()
        self.invariants = []
        self.discovered_violations = []
        self.solver = z3.Solver()
        
        logger.info("Protocol Semantics Engine initialized")
    
    async def model_protocol(
        self,
        protocol_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Build a formal model of the protocol"""
        logger.info("Building formal protocol model...")
        
        model = {
            'primitives': [],
            'states': [],
            'actions': [],
            'invariants': [],
            'dependencies': {},
            'attack_surface': []
        }
        
        # Identify protocol primitives
        model['primitives'] = await self._identify_primitives(protocol_data)
        
        # Model state space
        model['states'] = await self._model_state_space(protocol_data)
        
        # Model possible actions
        model['actions'] = await self._model_actions(protocol_data)
        
        # Derive invariants
        model['invariants'] = await self._derive_invariants(
            protocol_data,
            model['primitives']
        )
        
        # Map dependencies
        model['dependencies'] = await self._map_dependencies(protocol_data)
        
        # Identify attack surface
        model['attack_surface'] = await self._identify_attack_surface(
            model['actions'],
            model['invariants']
        )
        
        self.protocol_model = model
        return model
    
    async def _identify_primitives(
        self,
        protocol_data: Dict[str, Any]
    ) -> List[ProtocolPrimitive]:
        """Identify which DeFi primitives the protocol uses"""
        primitives = []
        
        # Analyze functions to identify primitives
        functions = protocol_data.get('functions', [])
        function_names = [f.get('name', '').lower() for f in functions]
        
        # Pattern matching for primitives
        primitive_patterns = {
            ProtocolPrimitive.LENDING: ['lend', 'supply', 'deposit'],
            ProtocolPrimitive.BORROWING: ['borrow', 'loan', 'debt'],
            ProtocolPrimitive.SWAPPING: ['swap', 'exchange', 'trade'],
            ProtocolPrimitive.LIQUIDITY_PROVISION: ['addliquidity', 'removeliquidity'],
            ProtocolPrimitive.STAKING: ['stake', 'unstake', 'delegate'],
            ProtocolPrimitive.GOVERNANCE: ['propose', 'vote', 'execute'],
            ProtocolPrimitive.ORACLE: ['getprice', 'updateprice', 'feed'],
            ProtocolPrimitive.FLASH_LOAN: ['flashloan', 'flashborrow'],
            ProtocolPrimitive.COLLATERAL: ['collateral', 'collateralize'],
            ProtocolPrimitive.LIQUIDATION: ['liquidate', 'liquidation'],
            ProtocolPrimitive.YIELD_FARMING: ['harvest', 'claim', 'reward'],
            ProtocolPrimitive.AUCTION: ['bid', 'auction', 'settle'],
            ProtocolPrimitive.BRIDGE: ['bridge', 'relay', 'crosschain'],
            ProtocolPrimitive.SYNTHETIC: ['mint', 'synthetic', 'derivative']
        }
        
        for primitive, patterns in primitive_patterns.items():
            if any(any(p in fn for p in patterns) for fn in function_names):
                primitives.append(primitive)
        
        return primitives
    
    async def _model_state_space(
        self,
        protocol_data: Dict[str, Any]
    ) -> List[ProtocolState]:
        """Model the protocol's state space"""
        states = []
        
        # Initial state
        initial_state = ProtocolState(
            timestamp=0,
            block_number=0
        )
        
        # Extract state variables
        state_vars = protocol_data.get('state_variables', [])
        
        for var in state_vars:
            var_name = var.get('name', '')
            var_type = var.get('type', '')
            
            # Initialize based on type
            if 'balance' in var_name.lower():
                initial_state.token_balances[var_name] = {}
            elif 'price' in var_name.lower():
                initial_state.prices[var_name] = 0.0
            elif 'reserve' in var_name.lower():
                initial_state.pool_reserves[var_name] = (0.0, 0.0)
        
        states.append(initial_state)
        
        # Generate possible state transitions
        # This would be expanded with actual state modeling
        
        return states
    
    async def _model_actions(
        self,
        protocol_data: Dict[str, Any]
    ) -> List[ProtocolAction]:
        """Model possible actions in the protocol"""
        actions = []
        
        functions = protocol_data.get('functions', [])
        
        for func in functions:
            if func.get('visibility') not in ['public', 'external']:
                continue
            
            # Determine primitive type
            primitive = self._classify_function_primitive(func)
            
            action = ProtocolAction(
                id=f"action_{func.get('name')}",
                name=func.get('name'),
                primitive=primitive,
                actor='user',
                target=func.get('contract', 'unknown'),
                parameters=self._extract_parameters(func),
                preconditions=self._derive_preconditions(func),
                postconditions=self._derive_postconditions(func),
                gas_cost=100000,  # Estimate
                capital_required=self._estimate_capital_required(func)
            )
            
            actions.append(action)
        
        return actions
    
    async def _derive_invariants(
        self,
        protocol_data: Dict[str, Any],
        primitives: List[ProtocolPrimitive]
    ) -> List[ProtocolInvariant]:
        """Derive protocol invariants based on primitives"""
        invariants = []
        
        # Common DeFi invariants
        if ProtocolPrimitive.LENDING in primitives:
            invariants.extend(self._lending_invariants())
        
        if ProtocolPrimitive.SWAPPING in primitives:
            invariants.extend(self._amm_invariants())
        
        if ProtocolPrimitive.GOVERNANCE in primitives:
            invariants.extend(self._governance_invariants())
        
        if ProtocolPrimitive.COLLATERAL in primitives:
            invariants.extend(self._collateral_invariants())
        
        # Protocol-specific invariants
        invariants.extend(await self._extract_custom_invariants(protocol_data))
        
        return invariants
    
    def _lending_invariants(self) -> List[ProtocolInvariant]:
        """Standard lending protocol invariants"""
        return [
            ProtocolInvariant(
                id="lending_solvency",
                name="Protocol Solvency",
                description="Total borrowed must not exceed total supplied",
                formula="sum(borrowed) <= sum(supplied)",
                scope="global",
                criticality="critical"
            ),
            ProtocolInvariant(
                id="lending_utilization",
                name="Utilization Bounds",
                description="Utilization rate must be between 0 and 100%",
                formula="0 <= utilization <= 1",
                scope="pool",
                criticality="high"
            ),
            ProtocolInvariant(
                id="lending_interest",
                name="Interest Accrual",
                description="Interest must accrue monotonically",
                formula="interest(t+1) >= interest(t)",
                scope="global",
                criticality="high"
            )
        ]
    
    def _amm_invariants(self) -> List[ProtocolInvariant]:
        """AMM protocol invariants"""
        return [
            ProtocolInvariant(
                id="amm_constant_product",
                name="Constant Product",
                description="x * y = k must hold for constant product AMMs",
                formula="reserve0 * reserve1 == k",
                scope="pool",
                criticality="critical"
            ),
            ProtocolInvariant(
                id="amm_price_consistency",
                name="Price Consistency",
                description="Spot price must match reserve ratio",
                formula="price == reserve1 / reserve0",
                scope="pool",
                criticality="high"
            ),
            ProtocolInvariant(
                id="amm_lp_value",
                name="LP Token Value",
                description="LP tokens must maintain proportional value",
                formula="lp_value == (reserves * lp_supply) / total_supply",
                scope="pool",
                criticality="high"
            )
        ]
    
    def _governance_invariants(self) -> List[ProtocolInvariant]:
        """Governance protocol invariants"""
        return [
            ProtocolInvariant(
                id="gov_voting_power",
                name="Voting Power Conservation",
                description="Total voting power must equal token supply",
                formula="sum(voting_power) == total_supply",
                scope="governance",
                criticality="critical"
            ),
            ProtocolInvariant(
                id="gov_quorum",
                name="Quorum Requirements",
                description="Executed proposals must meet quorum",
                formula="votes >= quorum_threshold",
                scope="governance",
                criticality="high"
            )
        ]
    
    def _collateral_invariants(self) -> List[ProtocolInvariant]:
        """Collateral protocol invariants"""
        return [
            ProtocolInvariant(
                id="collateral_ratio",
                name="Collateralization Ratio",
                description="Positions must maintain minimum collateral ratio",
                formula="collateral_value / debt_value >= min_ratio",
                scope="user",
                criticality="critical"
            ),
            ProtocolInvariant(
                id="liquidation_incentive",
                name="Liquidation Profitability",
                description="Liquidations must be profitable for liquidators",
                formula="liquidation_bonus > gas_cost",
                scope="global",
                criticality="medium"
            )
        ]
    
    async def _extract_custom_invariants(
        self,
        protocol_data: Dict[str, Any]
    ) -> List[ProtocolInvariant]:
        """Extract protocol-specific invariants from code"""
        invariants = []
        
        # Look for require statements and assertions
        functions = protocol_data.get('functions', [])
        
        for func in functions:
            code = func.get('code', '')
            
            # Extract require statements as invariants
            import re
            require_pattern = r'require\((.*?)\)'
            matches = re.findall(require_pattern, code)
            
            for i, match in enumerate(matches):
                invariants.append(ProtocolInvariant(
                    id=f"custom_{func.get('name')}_{i}",
                    name=f"Custom invariant in {func.get('name')}",
                    description=f"Extracted from require: {match[:100]}",
                    formula=match,
                    scope="function",
                    criticality="medium"
                ))
        
        return invariants
    
    async def find_invariant_violations(
        self,
        protocol_model: Dict[str, Any],
        execution_trace: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Find invariant violations in execution traces"""
        violations = []
        
        invariants = protocol_model.get('invariants', [])
        
        for invariant in invariants:
            # Check if invariant holds across trace
            for i, state in enumerate(execution_trace):
                if not self._check_invariant(invariant, state):
                    violations.append({
                        'invariant': invariant.name,
                        'formula': invariant.formula,
                        'state_index': i,
                        'state': state,
                        'criticality': invariant.criticality
                    })
        
        return violations
    
    def _check_invariant(
        self,
        invariant: ProtocolInvariant,
        state: Dict[str, Any]
    ) -> bool:
        """Check if an invariant holds in a given state"""
        # This would use Z3 or other formal verification tools
        # Simplified version for demonstration
        
        formula = invariant.formula
        
        # Parse and evaluate formula
        try:
            # Simple evaluation (would be replaced with proper formal verification)
            if "sum(borrowed) <= sum(supplied)" in formula:
                borrowed = sum(state.get('total_borrowed', {}).values())
                supplied = sum(state.get('total_supplied', {}).values())
                return borrowed <= supplied
            
            # Default to true if we can't evaluate
            return True
            
        except:
            return True
    
    async def discover_compositional_attacks(
        self,
        protocol_model: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Discover attacks through action composition"""
        logger.info("Discovering compositional attacks...")
        
        attacks = []
        actions = protocol_model.get('actions', [])
        invariants = protocol_model.get('invariants', [])
        
        # Generate action sequences
        sequences = self._generate_action_sequences(actions, max_length=5)
        
        for sequence in sequences:
            # Simulate sequence execution
            violation = await self._simulate_sequence(sequence, invariants)
            
            if violation:
                attacks.append({
                    'type': 'compositional',
                    'sequence': [a.name for a in sequence],
                    'violation': violation,
                    'severity': self._assess_severity(violation)
                })
        
        return attacks
    
    def _generate_action_sequences(
        self,
        actions: List[ProtocolAction],
        max_length: int = 5
    ) -> List[List[ProtocolAction]]:
        """Generate possible action sequences"""
        sequences = []
        
        # Start with single actions
        for action in actions:
            sequences.append([action])
        
        # Build longer sequences
        for length in range(2, max_length + 1):
            new_sequences = []
            
            for seq in sequences:
                if len(seq) == length - 1:
                    # Try adding each action
                    for action in actions:
                        # Check if action can follow sequence
                        if self._can_follow(seq[-1], action):
                            new_sequences.append(seq + [action])
            
            sequences.extend(new_sequences)
        
        # Filter to interesting sequences
        interesting = []
        for seq in sequences:
            if self._is_interesting_sequence(seq):
                interesting.append(seq)
        
        return interesting[:100]  # Limit for performance
    
    def _can_follow(
        self,
        action1: ProtocolAction,
        action2: ProtocolAction
    ) -> bool:
        """Check if action2 can follow action1"""
        # Check if postconditions of action1 satisfy preconditions of action2
        # Simplified version
        return True
    
    def _is_interesting_sequence(
        self,
        sequence: List[ProtocolAction]
    ) -> bool:
        """Check if a sequence is worth exploring"""
        # Look for patterns like:
        # - Flash loan at start
        # - Price manipulation in middle
        # - Profit extraction at end
        
        primitives = [a.primitive for a in sequence]
        
        # Flash loan attack pattern
        if (ProtocolPrimitive.FLASH_LOAN in primitives and
            ProtocolPrimitive.SWAPPING in primitives):
            return True
        
        # Governance attack pattern
        if (ProtocolPrimitive.GOVERNANCE in primitives and
            len(sequence) > 2):
            return True
        
        # Liquidation attack pattern
        if (ProtocolPrimitive.LIQUIDATION in primitives and
            ProtocolPrimitive.ORACLE in primitives):
            return True
        
        return False
    
    async def _simulate_sequence(
        self,
        sequence: List[ProtocolAction],
        invariants: List[ProtocolInvariant]
    ) -> Optional[Dict[str, Any]]:
        """Simulate action sequence and check for violations"""
        # This would integrate with the execution engine
        # Simplified version for demonstration
        
        state = {'initial': True}
        
        for action in sequence:
            # Apply action to state
            state = self._apply_action(state, action)
            
            # Check invariants
            for invariant in invariants:
                if not self._check_invariant(invariant, state):
                    return {
                        'invariant': invariant.name,
                        'action': action.name,
                        'state': state
                    }
        
        return None
    
    def _apply_action(
        self,
        state: Dict[str, Any],
        action: ProtocolAction
    ) -> Dict[str, Any]:
        """Apply an action to a state"""
        # Simplified state transition
        new_state = state.copy()
        new_state[action.name] = True
        return new_state
    
    def _assess_severity(self, violation: Dict[str, Any]) -> str:
        """Assess severity of an invariant violation"""
        # Based on invariant criticality and impact
        return "high"  # Simplified
    
    async def _map_dependencies(
        self,
        protocol_data: Dict[str, Any]
    ) -> Dict[str, List[str]]:
        """Map dependencies between protocol components"""
        dependencies = {}
        
        # Extract from external calls
        external_calls = protocol_data.get('external_calls', [])
        
        for call in external_calls:
            source = call.get('contract', 'unknown')
            target = call.get('target', 'unknown')
            
            if source not in dependencies:
                dependencies[source] = []
            dependencies[source].append(target)
        
        return dependencies
    
    async def _identify_attack_surface(
        self,
        actions: List[ProtocolAction],
        invariants: List[ProtocolInvariant]
    ) -> List[Dict[str, Any]]:
        """Identify the protocol's attack surface"""
        attack_surface = []
        
        # Entry points with high capital efficiency
        for action in actions:
            if action.capital_required == 0 or action.primitive == ProtocolPrimitive.FLASH_LOAN:
                attack_surface.append({
                    'type': 'low_capital_entry',
                    'action': action.name,
                    'risk': 'high'
                })
        
        # Actions that affect critical invariants
        critical_invariants = [i for i in invariants if i.criticality == 'critical']
        
        for action in actions:
            for invariant in critical_invariants:
                if self._action_affects_invariant(action, invariant):
                    attack_surface.append({
                        'type': 'critical_invariant_manipulation',
                        'action': action.name,
                        'invariant': invariant.name,
                        'risk': 'critical'
                    })
        
        return attack_surface
    
    def _action_affects_invariant(
        self,
        action: ProtocolAction,
        invariant: ProtocolInvariant
    ) -> bool:
        """Check if an action can affect an invariant"""
        # Simplified check - would use more sophisticated analysis
        return True
    
    def _classify_function_primitive(
        self,
        func: Dict[str, Any]
    ) -> ProtocolPrimitive:
        """Classify function into a protocol primitive"""
        func_name = func.get('name', '').lower()
        
        if 'swap' in func_name:
            return ProtocolPrimitive.SWAPPING
        elif 'lend' in func_name or 'supply' in func_name:
            return ProtocolPrimitive.LENDING
        elif 'borrow' in func_name:
            return ProtocolPrimitive.BORROWING
        elif 'stake' in func_name:
            return ProtocolPrimitive.STAKING
        elif 'vote' in func_name or 'propose' in func_name:
            return ProtocolPrimitive.GOVERNANCE
        elif 'liquidate' in func_name:
            return ProtocolPrimitive.LIQUIDATION
        else:
            return ProtocolPrimitive.SWAPPING  # Default
    
    def _extract_parameters(self, func: Dict[str, Any]) -> Dict[str, Any]:
        """Extract function parameters"""
        return {
            'inputs': func.get('params', []),
            'outputs': func.get('returns', [])
        }
    
    def _derive_preconditions(self, func: Dict[str, Any]) -> List[str]:
        """Derive function preconditions"""
        preconditions = []
        
        # Extract from modifiers
        modifiers = func.get('modifiers', [])
        for mod in modifiers:
            preconditions.append(f"modifier_{mod}")
        
        return preconditions
    
    def _derive_postconditions(self, func: Dict[str, Any]) -> List[str]:
        """Derive function postconditions"""
        # Would extract from function effects
        return []
    
    def _estimate_capital_required(self, func: Dict[str, Any]) -> float:
        """Estimate capital required for function"""
        if func.get('is_payable'):
            return 1.0  # Requires payment
        elif 'flash' in func.get('name', '').lower():
            return 0.0  # Flash loans require no capital
        else:
            return 0.0