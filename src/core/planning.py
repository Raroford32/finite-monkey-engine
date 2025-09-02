"""
Advanced Planning Engine for Exploit Execution

This module implements sophisticated planning capabilities for exploit discovery:
- Multi-step attack sequence planning
- Alternative path generation
- Backtracking and optimization
- Adaptive strategy selection
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import networkx as nx
from collections import deque
import heapq

logger = logging.getLogger(__name__)


class PlanningStrategy(Enum):
    """Planning strategies for exploit discovery"""
    ADAPTIVE = "adaptive"      # Adapts strategy based on target
    EXHAUSTIVE = "exhaustive"  # Explores all possible paths
    TARGETED = "targeted"      # Focuses on specific vulnerabilities
    HYBRID = "hybrid"          # Combines multiple strategies


@dataclass
class AttackStep:
    """Represents a single step in an attack sequence"""
    id: str
    action: str
    target: str
    parameters: Dict[str, Any]
    preconditions: List[str] = field(default_factory=list)
    postconditions: List[str] = field(default_factory=list)
    cost: float = 1.0
    risk: float = 0.0
    success_probability: float = 1.0


@dataclass
class AttackPlan:
    """Represents a complete attack plan"""
    id: str
    vulnerability_id: str
    steps: List[AttackStep]
    total_cost: float = 0.0
    total_risk: float = 0.0
    success_probability: float = 1.0
    alternatives: List['AttackPlan'] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class PlanningEngine:
    """
    Advanced planning engine for exploit execution
    
    Generates optimal attack sequences considering:
    - Multiple execution paths
    - Risk vs reward tradeoffs
    - Success probability
    - Resource constraints
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the planning engine"""
        self.config = config or {}
        self.max_steps = self.config.get('max_steps', 50)
        self.enable_multi_path = self.config.get('enable_multi_path', True)
        self.enable_backtracking = self.config.get('enable_backtracking', True)
        self.strategy = PlanningStrategy(self.config.get('strategy', 'adaptive'))
        
        # Action templates for different attack types
        self.action_templates = self._initialize_action_templates()
        
        # Planning graph for path finding
        self.planning_graph = nx.DiGraph()
        
        logger.info(f"Planning Engine initialized with strategy: {self.strategy}")
    
    def _initialize_action_templates(self) -> Dict[str, Dict[str, Any]]:
        """Initialize action templates for different attack types"""
        return {
            'reentrancy': {
                'setup': [
                    {'action': 'deploy_attacker_contract', 'cost': 2, 'risk': 0.1},
                    {'action': 'implement_callback', 'cost': 1, 'risk': 0.05}
                ],
                'execution': [
                    {'action': 'trigger_vulnerable_function', 'cost': 1, 'risk': 0.3},
                    {'action': 'reenter_target', 'cost': 1, 'risk': 0.4},
                    {'action': 'drain_funds', 'cost': 1, 'risk': 0.5}
                ],
                'cleanup': [
                    {'action': 'withdraw_stolen_funds', 'cost': 1, 'risk': 0.2}
                ]
            },
            'flash_loan': {
                'setup': [
                    {'action': 'identify_flash_loan_provider', 'cost': 1, 'risk': 0.0},
                    {'action': 'calculate_required_amount', 'cost': 1, 'risk': 0.0}
                ],
                'execution': [
                    {'action': 'request_flash_loan', 'cost': 2, 'risk': 0.1},
                    {'action': 'manipulate_price', 'cost': 2, 'risk': 0.4},
                    {'action': 'exploit_price_dependency', 'cost': 1, 'risk': 0.5},
                    {'action': 'repay_flash_loan', 'cost': 1, 'risk': 0.1}
                ],
                'cleanup': [
                    {'action': 'convert_profits', 'cost': 1, 'risk': 0.1}
                ]
            },
            'oracle_manipulation': {
                'setup': [
                    {'action': 'analyze_oracle_dependencies', 'cost': 2, 'risk': 0.0},
                    {'action': 'identify_manipulation_vector', 'cost': 2, 'risk': 0.0}
                ],
                'execution': [
                    {'action': 'manipulate_oracle_source', 'cost': 3, 'risk': 0.4},
                    {'action': 'trigger_oracle_update', 'cost': 1, 'risk': 0.2},
                    {'action': 'exploit_manipulated_price', 'cost': 2, 'risk': 0.5}
                ],
                'cleanup': [
                    {'action': 'restore_oracle_state', 'cost': 1, 'risk': 0.1}
                ]
            },
            'governance': {
                'setup': [
                    {'action': 'accumulate_voting_power', 'cost': 5, 'risk': 0.2},
                    {'action': 'create_malicious_proposal', 'cost': 2, 'risk': 0.3}
                ],
                'execution': [
                    {'action': 'submit_proposal', 'cost': 1, 'risk': 0.2},
                    {'action': 'vote_on_proposal', 'cost': 1, 'risk': 0.1},
                    {'action': 'execute_proposal', 'cost': 1, 'risk': 0.5}
                ],
                'cleanup': [
                    {'action': 'extract_value', 'cost': 2, 'risk': 0.3}
                ]
            },
            'access_control': {
                'setup': [
                    {'action': 'identify_access_vulnerability', 'cost': 1, 'risk': 0.0}
                ],
                'execution': [
                    {'action': 'bypass_access_control', 'cost': 2, 'risk': 0.4},
                    {'action': 'execute_privileged_function', 'cost': 1, 'risk': 0.5}
                ],
                'cleanup': [
                    {'action': 'cover_tracks', 'cost': 1, 'risk': 0.1}
                ]
            }
        }
    
    async def generate_plan(
        self,
        hypothesis: Dict[str, Any],
        analysis_results: Dict[str, Any],
        strategy: Optional[str] = None
    ) -> AttackPlan:
        """Generate an attack plan for a vulnerability hypothesis"""
        logger.info(f"Generating attack plan for {hypothesis.get('id')}")
        
        # Use specified strategy or default
        planning_strategy = PlanningStrategy(strategy) if strategy else self.strategy
        
        # Select planning method based on strategy
        if planning_strategy == PlanningStrategy.ADAPTIVE:
            plan = await self._adaptive_planning(hypothesis, analysis_results)
        elif planning_strategy == PlanningStrategy.EXHAUSTIVE:
            plan = await self._exhaustive_planning(hypothesis, analysis_results)
        elif planning_strategy == PlanningStrategy.TARGETED:
            plan = await self._targeted_planning(hypothesis, analysis_results)
        else:  # HYBRID
            plan = await self._hybrid_planning(hypothesis, analysis_results)
        
        # Calculate plan metrics
        self._calculate_plan_metrics(plan)
        
        return plan
    
    async def _adaptive_planning(
        self,
        hypothesis: Dict[str, Any],
        analysis_results: Dict[str, Any]
    ) -> AttackPlan:
        """Adaptive planning that adjusts based on target characteristics"""
        vuln_type = hypothesis.get('vulnerability_class', {}).get('value', 'unknown')
        
        # Get appropriate action template
        template = self._get_action_template(vuln_type)
        
        # Build attack sequence
        steps = []
        step_id = 0
        
        # Add setup steps
        for action_template in template.get('setup', []):
            step = self._create_attack_step(
                step_id,
                action_template,
                hypothesis,
                analysis_results
            )
            steps.append(step)
            step_id += 1
        
        # Add execution steps
        for action_template in template.get('execution', []):
            step = self._create_attack_step(
                step_id,
                action_template,
                hypothesis,
                analysis_results
            )
            steps.append(step)
            step_id += 1
        
        # Add cleanup steps
        for action_template in template.get('cleanup', []):
            step = self._create_attack_step(
                step_id,
                action_template,
                hypothesis,
                analysis_results
            )
            steps.append(step)
            step_id += 1
        
        # Create plan
        plan = AttackPlan(
            id=f"plan_{hypothesis.get('id')}",
            vulnerability_id=hypothesis.get('id'),
            steps=steps,
            metadata={'strategy': 'adaptive', 'hypothesis': hypothesis}
        )
        
        return plan
    
    async def _exhaustive_planning(
        self,
        hypothesis: Dict[str, Any],
        analysis_results: Dict[str, Any]
    ) -> AttackPlan:
        """Exhaustive planning that explores all possible paths"""
        # Build state space
        state_space = self._build_state_space(hypothesis, analysis_results)
        
        # Find all paths from initial to goal state
        all_paths = self._find_all_paths(state_space)
        
        # Select best path
        best_path = self._select_best_path(all_paths)
        
        # Convert path to attack steps
        steps = self._path_to_steps(best_path, hypothesis, analysis_results)
        
        plan = AttackPlan(
            id=f"plan_{hypothesis.get('id')}",
            vulnerability_id=hypothesis.get('id'),
            steps=steps,
            metadata={'strategy': 'exhaustive', 'paths_explored': len(all_paths)}
        )
        
        return plan
    
    async def _targeted_planning(
        self,
        hypothesis: Dict[str, Any],
        analysis_results: Dict[str, Any]
    ) -> AttackPlan:
        """Targeted planning focused on specific vulnerability"""
        target_function = hypothesis.get('target_function')
        target_contract = hypothesis.get('target_contract')
        
        # Build minimal attack sequence
        steps = []
        
        # Direct exploitation
        step = AttackStep(
            id="0",
            action="exploit_vulnerability",
            target=f"{target_contract}.{target_function}",
            parameters={
                'vulnerability_type': hypothesis.get('vulnerability_class'),
                'exploit_data': hypothesis.get('evidence')
            }
        )
        steps.append(step)
        
        plan = AttackPlan(
            id=f"plan_{hypothesis.get('id')}",
            vulnerability_id=hypothesis.get('id'),
            steps=steps,
            metadata={'strategy': 'targeted'}
        )
        
        return plan
    
    async def _hybrid_planning(
        self,
        hypothesis: Dict[str, Any],
        analysis_results: Dict[str, Any]
    ) -> AttackPlan:
        """Hybrid planning combining multiple strategies"""
        # Generate plans using different strategies
        adaptive_plan = await self._adaptive_planning(hypothesis, analysis_results)
        targeted_plan = await self._targeted_planning(hypothesis, analysis_results)
        
        # Combine best aspects of each plan
        hybrid_steps = self._merge_plans(adaptive_plan, targeted_plan)
        
        plan = AttackPlan(
            id=f"plan_{hypothesis.get('id')}",
            vulnerability_id=hypothesis.get('id'),
            steps=hybrid_steps,
            metadata={'strategy': 'hybrid'}
        )
        
        return plan
    
    async def optimize_plan(
        self,
        plan: AttackPlan,
        analysis_results: Dict[str, Any]
    ) -> AttackPlan:
        """Optimize an attack plan for maximum effectiveness"""
        logger.info(f"Optimizing plan {plan.id}")
        
        # Remove redundant steps
        optimized_steps = self._remove_redundant_steps(plan.steps)
        
        # Reorder for optimal execution
        optimized_steps = self._optimize_step_order(optimized_steps)
        
        # Minimize risk while maintaining effectiveness
        optimized_steps = self._minimize_risk(optimized_steps)
        
        # Create optimized plan
        optimized_plan = AttackPlan(
            id=f"{plan.id}_optimized",
            vulnerability_id=plan.vulnerability_id,
            steps=optimized_steps,
            metadata=plan.metadata
        )
        
        # Recalculate metrics
        self._calculate_plan_metrics(optimized_plan)
        
        return optimized_plan
    
    async def generate_alternatives(
        self,
        plan: AttackPlan,
        analysis_results: Dict[str, Any]
    ) -> List[AttackPlan]:
        """Generate alternative attack plans"""
        if not self.enable_multi_path:
            return []
        
        logger.info(f"Generating alternatives for plan {plan.id}")
        
        alternatives = []
        
        # Variation 1: Different parameter values
        param_variation = self._generate_parameter_variations(plan)
        alternatives.extend(param_variation)
        
        # Variation 2: Different step ordering
        order_variation = self._generate_order_variations(plan)
        alternatives.extend(order_variation)
        
        # Variation 3: Alternative actions
        action_variation = self._generate_action_variations(plan)
        alternatives.extend(action_variation)
        
        # Limit number of alternatives
        alternatives = alternatives[:5]
        
        return alternatives
    
    def _get_action_template(self, vuln_type: str) -> Dict[str, Any]:
        """Get action template for vulnerability type"""
        # Map vulnerability types to templates
        template_map = {
            'reentrancy': 'reentrancy',
            'flash_loan_attack': 'flash_loan',
            'price_manipulation': 'oracle_manipulation',
            'oracle_manipulation': 'oracle_manipulation',
            'governance_attack': 'governance',
            'access_control': 'access_control'
        }
        
        template_key = template_map.get(vuln_type, 'access_control')
        return self.action_templates.get(template_key, {})
    
    def _create_attack_step(
        self,
        step_id: int,
        action_template: Dict[str, Any],
        hypothesis: Dict[str, Any],
        analysis_results: Dict[str, Any]
    ) -> AttackStep:
        """Create an attack step from template"""
        return AttackStep(
            id=str(step_id),
            action=action_template['action'],
            target=hypothesis.get('target_contract', 'unknown'),
            parameters={
                'function': hypothesis.get('target_function'),
                'vulnerability': hypothesis.get('vulnerability_class')
            },
            cost=action_template.get('cost', 1),
            risk=action_template.get('risk', 0),
            success_probability=1.0 - action_template.get('risk', 0)
        )
    
    def _build_state_space(
        self,
        hypothesis: Dict[str, Any],
        analysis_results: Dict[str, Any]
    ) -> nx.DiGraph:
        """Build state space for planning"""
        G = nx.DiGraph()
        
        # Add initial state
        G.add_node('initial', type='start')
        
        # Add goal state
        G.add_node('goal', type='end')
        
        # Add intermediate states based on analysis
        functions = analysis_results.get('functions', [])
        for i, func in enumerate(functions[:10]):  # Limit for performance
            state_id = f"state_{i}"
            G.add_node(state_id, function=func)
            
            # Connect states
            if i == 0:
                G.add_edge('initial', state_id)
            if i == len(functions) - 1:
                G.add_edge(state_id, 'goal')
            if i > 0:
                G.add_edge(f"state_{i-1}", state_id)
        
        return G
    
    def _find_all_paths(self, state_space: nx.DiGraph) -> List[List[str]]:
        """Find all paths through state space"""
        try:
            paths = list(nx.all_simple_paths(
                state_space,
                'initial',
                'goal',
                cutoff=self.max_steps
            ))
            return paths[:100]  # Limit number of paths
        except:
            return []
    
    def _select_best_path(self, paths: List[List[str]]) -> List[str]:
        """Select best path based on heuristics"""
        if not paths:
            return []
        
        # Simple heuristic: shortest path
        return min(paths, key=len)
    
    def _path_to_steps(
        self,
        path: List[str],
        hypothesis: Dict[str, Any],
        analysis_results: Dict[str, Any]
    ) -> List[AttackStep]:
        """Convert state path to attack steps"""
        steps = []
        
        for i, state in enumerate(path[1:-1]):  # Skip initial and goal
            step = AttackStep(
                id=str(i),
                action=f"transition_to_{state}",
                target=hypothesis.get('target_contract', 'unknown'),
                parameters={'state': state}
            )
            steps.append(step)
        
        return steps
    
    def _merge_plans(
        self,
        plan1: AttackPlan,
        plan2: AttackPlan
    ) -> List[AttackStep]:
        """Merge two plans into hybrid approach"""
        # Simple merge: take setup from plan1, execution from plan2
        merged_steps = []
        
        # Take first half from plan1
        merged_steps.extend(plan1.steps[:len(plan1.steps)//2])
        
        # Take second half from plan2
        merged_steps.extend(plan2.steps[len(plan2.steps)//2:])
        
        # Renumber steps
        for i, step in enumerate(merged_steps):
            step.id = str(i)
        
        return merged_steps
    
    def _calculate_plan_metrics(self, plan: AttackPlan):
        """Calculate metrics for a plan"""
        plan.total_cost = sum(step.cost for step in plan.steps)
        plan.total_risk = 1 - np.prod([1 - step.risk for step in plan.steps])
        plan.success_probability = np.prod([step.success_probability for step in plan.steps])
    
    def _remove_redundant_steps(self, steps: List[AttackStep]) -> List[AttackStep]:
        """Remove redundant steps from plan"""
        seen_actions = set()
        unique_steps = []
        
        for step in steps:
            action_key = (step.action, step.target)
            if action_key not in seen_actions:
                seen_actions.add(action_key)
                unique_steps.append(step)
        
        return unique_steps
    
    def _optimize_step_order(self, steps: List[AttackStep]) -> List[AttackStep]:
        """Optimize order of steps for execution"""
        # Sort by dependencies and risk
        # Lower risk steps first
        return sorted(steps, key=lambda s: (s.risk, -s.success_probability))
    
    def _minimize_risk(self, steps: List[AttackStep]) -> List[AttackStep]:
        """Minimize risk in attack sequence"""
        # Filter out high-risk low-reward steps
        return [s for s in steps if s.risk < 0.7 or s.success_probability > 0.8]
    
    def _generate_parameter_variations(self, plan: AttackPlan) -> List[AttackPlan]:
        """Generate plans with parameter variations"""
        variations = []
        
        # Create variation with different parameters
        new_steps = []
        for step in plan.steps:
            new_step = AttackStep(
                id=step.id,
                action=step.action,
                target=step.target,
                parameters={**step.parameters, 'variation': 'parameter'},
                cost=step.cost,
                risk=step.risk * 1.1,  # Slightly higher risk
                success_probability=step.success_probability * 0.95
            )
            new_steps.append(new_step)
        
        variation = AttackPlan(
            id=f"{plan.id}_param_var",
            vulnerability_id=plan.vulnerability_id,
            steps=new_steps,
            metadata={**plan.metadata, 'variation_type': 'parameter'}
        )
        variations.append(variation)
        
        return variations
    
    def _generate_order_variations(self, plan: AttackPlan) -> List[AttackPlan]:
        """Generate plans with different step ordering"""
        variations = []
        
        # Reverse non-dependent steps
        if len(plan.steps) > 2:
            new_steps = [plan.steps[0]] + list(reversed(plan.steps[1:-1])) + [plan.steps[-1]]
            
            variation = AttackPlan(
                id=f"{plan.id}_order_var",
                vulnerability_id=plan.vulnerability_id,
                steps=new_steps,
                metadata={**plan.metadata, 'variation_type': 'order'}
            )
            variations.append(variation)
        
        return variations
    
    def _generate_action_variations(self, plan: AttackPlan) -> List[AttackPlan]:
        """Generate plans with alternative actions"""
        variations = []
        
        # Replace some actions with alternatives
        new_steps = []
        for step in plan.steps:
            if 'exploit' in step.action:
                # Alternative exploitation method
                new_step = AttackStep(
                    id=step.id,
                    action='alternative_exploit',
                    target=step.target,
                    parameters=step.parameters,
                    cost=step.cost * 1.2,
                    risk=step.risk * 0.8,
                    success_probability=step.success_probability * 1.1
                )
                new_steps.append(new_step)
            else:
                new_steps.append(step)
        
        if new_steps != plan.steps:
            variation = AttackPlan(
                id=f"{plan.id}_action_var",
                vulnerability_id=plan.vulnerability_id,
                steps=new_steps,
                metadata={**plan.metadata, 'variation_type': 'action'}
            )
            variations.append(variation)
        
        return variations


# Import numpy for calculations
import numpy as np