"""
Main Exploit Discovery Engine - Orchestrates all components for autonomous exploit discovery
"""

import asyncio
import json
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import logging

from .reasoning import ReasoningEngine
from .planning import PlanningEngine
from .execution import ExecutionEngine
from .validation import ValidationEngine
from .analyzer import ProtocolAnalyzer, CodebaseAnalyzer
from .patterns import ExploitPatternMatcher
from .memory import MemorySystem
from .protocol_semantics import ProtocolSemanticsEngine
from .economic_modeling import EconomicModelingEngine, MarketState
from .agentic_orchestrator import get_agentic_orchestrator
from .advanced_orchestrator import get_advanced_orchestrator
from .brilliant_memory import BrilliantMemory

logger = logging.getLogger(__name__)


@dataclass
class ExploitCandidate:
    """Represents a potential exploit discovered by the system"""
    id: str
    vulnerability_type: str
    severity: str  # critical, high, medium, low
    confidence: float  # 0.0 to 1.0
    target_contract: Optional[str] = None
    target_function: Optional[str] = None
    attack_vector: Optional[str] = None
    preconditions: List[str] = field(default_factory=list)
    steps: List[Dict[str, Any]] = field(default_factory=list)
    proof_of_concept: Optional[str] = None
    funds_at_risk: Optional[float] = None
    discovery_timestamp: datetime = field(default_factory=datetime.now)
    validation_status: str = "pending"  # pending, validated, failed, partial
    execution_trace: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ExploitDiscoveryEngine:
    """
    Advanced Agentic Exploit Discovery Engine
    
    This engine orchestrates multiple AI agents to autonomously discover
    novel exploits through reasoning, planning, execution, and validation.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the exploit discovery engine with configuration"""
        self.config = config or self._default_config()
        
        # Check if using agentic mode
        self.use_agentic = self.config.get('use_agentic', True)
        self.use_advanced = self.config.get('use_advanced', True)
        
        if self.use_advanced:
            # Use most advanced hierarchical orchestrator
            self.orchestrator = get_advanced_orchestrator(self.config)
            self.brilliant_memory = BrilliantMemory(embedding_dim=1024)
            logger.info("Initialized in ADVANCED MODE - Hierarchical multi-agent system")
        elif self.use_agentic:
            # Initialize agentic orchestrator for fully LLM-driven discovery
            self.orchestrator = get_agentic_orchestrator(self.config)
            self.brilliant_memory = BrilliantMemory()
            logger.info("Initialized in AGENTIC MODE - Fully LLM-driven discovery")
        
        # Initialize core components (used in both modes)
        self.reasoning_engine = ReasoningEngine(self.config.get('reasoning', {}))
        self.planning_engine = PlanningEngine(self.config.get('planning', {}))
        self.execution_engine = ExecutionEngine(self.config.get('execution', {}))
        self.validation_engine = ValidationEngine(self.config.get('validation', {}))
        
        # Initialize analyzers
        self.protocol_analyzer = ProtocolAnalyzer(self.config.get('protocol', {}))
        self.codebase_analyzer = CodebaseAnalyzer(self.config.get('codebase', {}))
        
        # Initialize pattern matching and memory systems
        self.pattern_matcher = ExploitPatternMatcher()
        self.memory = MemorySystem()
        
        # Initialize advanced analysis engines
        self.semantics_engine = ProtocolSemanticsEngine()
        self.economic_engine = EconomicModelingEngine()
        
        # Track discovered exploits
        self.discovered_exploits: List[ExploitCandidate] = []
        self.analysis_history: List[Dict[str, Any]] = []
        
        logger.info("Exploit Discovery Engine initialized with advanced capabilities")
    
    def _default_config(self) -> Dict[str, Any]:
        """Return default configuration for the engine"""
        return {
            'reasoning': {
                'max_depth': 10,
                'enable_symbolic': True,
                'enable_fuzzing': True,
                'enable_invariant_detection': True
            },
            'planning': {
                'max_steps': 50,
                'enable_multi_path': True,
                'enable_backtracking': True,
                'strategy': 'adaptive'  # adaptive, exhaustive, targeted
            },
            'execution': {
                'mode': 'fork',  # fork, simulation, hybrid
                'timeout': 300,
                'gas_limit': 30000000,
                'enable_state_diff': True
            },
            'validation': {
                'min_confidence': 0.7,
                'require_poc': True,
                'cross_validate': True,
                'validation_rounds': 3
            },
            'protocol': {
                'analyze_dependencies': True,
                'track_state_changes': True,
                'detect_reentrancy': True,
                'analyze_access_control': True
            },
            'codebase': {
                'languages': ['solidity', 'rust', 'move', 'vyper'],
                'analyze_imports': True,
                'track_external_calls': True,
                'build_call_graph': True
            }
        }
    
    async def discover_exploits(
        self,
        target: str,
        target_type: str = 'auto',  # auto, contract, protocol, codebase
        context: Optional[Dict[str, Any]] = None
    ) -> List[ExploitCandidate]:
        """
        Main entry point for discovering exploits in a target
        
        In agentic mode: Uses fully LLM-driven multi-agent system
        In traditional mode: Uses rule-based analysis with LLM enhancement
        
        Args:
            target: Path to codebase, contract address, or protocol identifier
            target_type: Type of target to analyze
            context: Additional context for analysis
        
        Returns:
            List of discovered exploit candidates
        """
        logger.info(f"Starting exploit discovery for {target} (type: {target_type})")
        
        # Use agentic mode if enabled
        if self.use_agentic:
            return await self._discover_exploits_agentic(target, target_type, context)
        
        # Traditional discovery process
        return await self._discover_exploits_traditional(target, target_type, context)
    
    async def _discover_exploits_agentic(
        self,
        target: str,
        target_type: str = "auto",
        context: Optional[Dict[str, Any]] = None
    ) -> List[ExploitCandidate]:
        """
        Fully LLM-driven exploit discovery using multi-agent system
        
        All decisions are made by specialized LLM agents collaborating
        to find novel exploits through creative reasoning.
        """
        logger.info("Using AGENTIC discovery mode - LLMs making all decisions")
        
        # Prepare context with brilliant memory insights
        enhanced_context = context or {}
        
        # Add memory insights if available
        if hasattr(self, 'brilliant_memory'):
            memory_query = {
                'target': target,
                'type': target_type,
                'seeking': 'novel exploits'
            }
            
            # Recall similar past discoveries
            similar_discoveries = await self.brilliant_memory.recall(memory_query, k=5)
            
            enhanced_context['memory_insights'] = [
                {
                    'content': node.content,
                    'importance': node.importance,
                    'success_metrics': node.success_metrics
                }
                for node, score in similar_discoveries
            ]
            
            # Generate novel combination from memory
            novel_idea = await self.brilliant_memory.generate_novel_combination(enhanced_context)
            if novel_idea:
                enhanced_context['novel_seed'] = novel_idea
        
        # Run discovery with appropriate orchestrator
        if self.use_advanced:
            # Use advanced hierarchical orchestrator for large-scale analysis
            agentic_exploits = await self.orchestrator.analyze_large_codebase(
                target,
                chunk_size=1000
            )
        else:
            # Use standard agentic orchestrator
            agentic_exploits = await self.orchestrator.discover_novel_exploits(
                target,
                enhanced_context
            )
        
        # Convert to ExploitCandidate format
        candidates = []
        for exploit in agentic_exploits:
            candidate = ExploitCandidate(
                id=exploit.get('id', self._generate_id()),
                vulnerability_type=exploit.get('vulnerability_type', 'unknown'),
                severity=exploit.get('severity', 'high'),
                confidence=exploit.get('confidence', 0.7),
                target_contract=exploit.get('target_contract'),
                target_function=exploit.get('target_function'),
                attack_vector=exploit.get('attack_vector'),
                preconditions=exploit.get('preconditions', []),
                steps=exploit.get('steps', []),
                proof_of_concept=exploit.get('poc'),
                funds_at_risk=exploit.get('funds_at_risk', 0),
                metadata=exploit
            )
            candidates.append(candidate)
            
            # Store in brilliant memory for learning
            await self.brilliant_memory.store(
                exploit,
                context={'discovery_mode': 'agentic', 'target': target},
                importance=candidate.confidence
            )
        
        # Update discovered exploits
        self.discovered_exploits.extend(candidates)
        
        logger.info(f"Agentic discovery found {len(candidates)} novel exploits")
        return candidates
    
    async def _discover_exploits_traditional(
        self,
        target: str,
        target_type: str = 'auto',
        context: Optional[Dict[str, Any]] = None
    ) -> List[ExploitCandidate]:
        """
        Traditional exploit discovery with LLM enhancement
        """
        logger.info(f"Using traditional discovery mode for {target} (type: {target_type})")
        
        # Phase 1: Analysis and Understanding
        analysis_results = await self._analyze_target(target, target_type, context)
        
        # Phase 1.5: Deep Protocol Semantics Analysis
        if target_type in ['protocol', 'contract']:
            protocol_model = await self.semantics_engine.model_protocol(analysis_results)
            analysis_results['protocol_model'] = protocol_model
            
            # Discover compositional attacks
            compositional_attacks = await self.semantics_engine.discover_compositional_attacks(protocol_model)
            analysis_results['compositional_attacks'] = compositional_attacks
        
        # Phase 1.6: Economic Analysis
        market_state = self._get_market_state()
        if 'protocol_model' in analysis_results:
            economic_opportunities = await self.economic_engine.analyze_economic_incentives(
                analysis_results['protocol_model'],
                market_state
            )
            analysis_results['economic_opportunities'] = economic_opportunities
        
        # Phase 2: Reasoning about vulnerabilities
        vulnerability_hypotheses = await self._reason_about_vulnerabilities(analysis_results)
        
        # Phase 3: Planning attack sequences
        attack_plans = await self._plan_attacks(vulnerability_hypotheses, analysis_results)
        
        # Phase 4: Execute and test exploits
        execution_results = await self._execute_exploits(attack_plans, analysis_results)
        
        # Phase 5: Validate and verify exploits
        validated_exploits = await self._validate_exploits(execution_results)
        
        # Phase 6: Generate proof of concepts
        final_exploits = await self._generate_pocs(validated_exploits)
        
        # Store results
        self.discovered_exploits.extend(final_exploits)
        self.analysis_history.append({
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'exploits_found': len(final_exploits),
            'analysis_results': analysis_results,
            'context': context
        })
        
        # Update memory with learnings
        await self._update_memory(final_exploits, analysis_results)
        
        logger.info(f"Discovered {len(final_exploits)} exploits for {target}")
        return final_exploits
    
    async def _analyze_target(
        self,
        target: str,
        target_type: str,
        context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Analyze the target to understand its structure and behavior"""
        logger.info("Phase 1: Analyzing target...")
        
        results = {
            'target': target,
            'type': target_type,
            'timestamp': datetime.now().isoformat()
        }
        
        # Determine target type if auto
        if target_type == 'auto':
            target_type = self._detect_target_type(target)
            results['detected_type'] = target_type
        
        # Analyze based on target type
        if target_type in ['contract', 'protocol']:
            protocol_analysis = await self.protocol_analyzer.analyze(target, context)
            results['protocol_analysis'] = protocol_analysis
            
            # Extract key information
            results['contracts'] = protocol_analysis.get('contracts', [])
            results['entry_points'] = protocol_analysis.get('entry_points', [])
            results['state_variables'] = protocol_analysis.get('state_variables', [])
            results['external_calls'] = protocol_analysis.get('external_calls', [])
            
        if target_type in ['codebase', 'protocol']:
            codebase_analysis = await self.codebase_analyzer.analyze(target, context)
            results['codebase_analysis'] = codebase_analysis
            
            # Build comprehensive understanding
            results['functions'] = codebase_analysis.get('functions', [])
            results['call_graph'] = codebase_analysis.get('call_graph', {})
            results['data_flow'] = codebase_analysis.get('data_flow', {})
            results['control_flow'] = codebase_analysis.get('control_flow', {})
        
        # Identify interesting patterns
        patterns = self.pattern_matcher.find_patterns(results)
        results['patterns'] = patterns
        
        # Check against known vulnerability databases
        known_vulns = await self.memory.check_known_vulnerabilities(results)
        results['known_vulnerabilities'] = known_vulns
        
        return results
    
    async def _reason_about_vulnerabilities(
        self,
        analysis_results: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Use reasoning engine to hypothesize about potential vulnerabilities"""
        logger.info("Phase 2: Reasoning about vulnerabilities...")
        
        # Generate vulnerability hypotheses
        hypotheses = await self.reasoning_engine.generate_hypotheses(analysis_results)
        
        # Add hypotheses from compositional attacks
        if 'compositional_attacks' in analysis_results:
            for attack in analysis_results['compositional_attacks']:
                hypotheses.append({
                    'id': f"comp_{attack.get('sequence', ['unknown'])[0]}",
                    'vulnerability_class': {'value': 'compositional'},
                    'confidence': 0.8,
                    'evidence': attack
                })
        
        # Add hypotheses from economic opportunities
        if 'economic_opportunities' in analysis_results:
            for opp in analysis_results['economic_opportunities'][:5]:  # Top 5
                if opp.profit_estimate > 10000:  # Significant profit
                    hypotheses.append({
                        'id': f"econ_{opp.id}",
                        'vulnerability_class': {'value': str(opp.type.value)},
                        'confidence': 0.9,
                        'evidence': {'opportunity': opp}
                    })
        
        # Rank hypotheses by likelihood and impact
        ranked_hypotheses = await self.reasoning_engine.rank_hypotheses(
            hypotheses,
            analysis_results
        )
        
        # Apply advanced reasoning techniques
        for hypothesis in ranked_hypotheses:
            # Symbolic reasoning
            if self.config['reasoning']['enable_symbolic']:
                symbolic_analysis = await self.reasoning_engine.symbolic_analysis(
                    hypothesis,
                    analysis_results
                )
                hypothesis['symbolic_evidence'] = symbolic_analysis
            
            # Invariant detection
            if self.config['reasoning']['enable_invariant_detection']:
                invariants = await self.reasoning_engine.detect_invariants(
                    hypothesis,
                    analysis_results
                )
                hypothesis['invariants'] = invariants
            
            # Fuzzing-based exploration
            if self.config['reasoning']['enable_fuzzing']:
                fuzz_results = await self.reasoning_engine.fuzz_hypothesis(
                    hypothesis,
                    analysis_results
                )
                hypothesis['fuzz_evidence'] = fuzz_results
        
        return ranked_hypotheses
    
    async def _plan_attacks(
        self,
        vulnerability_hypotheses: List[Dict[str, Any]],
        analysis_results: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Plan attack sequences for each vulnerability hypothesis"""
        logger.info("Phase 3: Planning attack sequences...")
        
        attack_plans = []
        
        for hypothesis in vulnerability_hypotheses:
            # Generate attack plan
            plan = await self.planning_engine.generate_plan(
                hypothesis,
                analysis_results,
                strategy=self.config['planning']['strategy']
            )
            
            # Optimize plan for maximum impact
            optimized_plan = await self.planning_engine.optimize_plan(
                plan,
                analysis_results
            )
            
            # Generate alternative paths if enabled
            if self.config['planning']['enable_multi_path']:
                alternatives = await self.planning_engine.generate_alternatives(
                    optimized_plan,
                    analysis_results
                )
                optimized_plan['alternatives'] = alternatives
            
            attack_plans.append(optimized_plan)
        
        return attack_plans
    
    async def _execute_exploits(
        self,
        attack_plans: List[Dict[str, Any]],
        analysis_results: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Execute attack plans to test exploits"""
        logger.info("Phase 4: Executing exploit attempts...")
        
        execution_results = []
        
        for plan in attack_plans:
            # Execute main plan
            result = await self.execution_engine.execute(
                plan,
                analysis_results,
                mode=self.config['execution']['mode']
            )
            
            # Try alternative paths if main fails
            if not result['success'] and 'alternatives' in plan:
                for alt_plan in plan['alternatives']:
                    alt_result = await self.execution_engine.execute(
                        alt_plan,
                        analysis_results,
                        mode=self.config['execution']['mode']
                    )
                    if alt_result['success']:
                        result = alt_result
                        break
            
            execution_results.append(result)
        
        return execution_results
    
    async def _validate_exploits(
        self,
        execution_results: List[Dict[str, Any]]
    ) -> List[ExploitCandidate]:
        """Validate and verify discovered exploits"""
        logger.info("Phase 5: Validating exploits...")
        
        validated_exploits = []
        
        for result in execution_results:
            if not result.get('success'):
                continue
            
            # Perform validation
            validation = await self.validation_engine.validate(
                result,
                rounds=self.config['validation']['validation_rounds']
            )
            
            # Check confidence threshold
            if validation['confidence'] < self.config['validation']['min_confidence']:
                continue
            
            # Create exploit candidate
            exploit = ExploitCandidate(
                id=self._generate_exploit_id(),
                vulnerability_type=result.get('vulnerability_type', 'unknown'),
                severity=self._calculate_severity(result, validation),
                confidence=validation['confidence'],
                target_contract=result.get('target_contract'),
                target_function=result.get('target_function'),
                attack_vector=result.get('attack_vector'),
                preconditions=result.get('preconditions', []),
                steps=result.get('steps', []),
                funds_at_risk=validation.get('funds_at_risk'),
                validation_status='validated',
                execution_trace=result.get('trace', []),
                metadata={
                    'validation': validation,
                    'execution': result
                }
            )
            
            validated_exploits.append(exploit)
        
        return validated_exploits
    
    async def _generate_pocs(
        self,
        validated_exploits: List[ExploitCandidate]
    ) -> List[ExploitCandidate]:
        """Generate proof of concept code for validated exploits"""
        logger.info("Phase 6: Generating proof of concepts...")
        
        for exploit in validated_exploits:
            if self.config['validation']['require_poc']:
                poc = await self.execution_engine.generate_poc(exploit)
                exploit.proof_of_concept = poc
        
        return validated_exploits
    
    async def _update_memory(
        self,
        exploits: List[ExploitCandidate],
        analysis_results: Dict[str, Any]
    ):
        """Update memory system with new learnings"""
        await self.memory.store_exploits(exploits)
        await self.memory.store_analysis(analysis_results)
        await self.pattern_matcher.update_patterns(exploits)
    
    def _detect_target_type(self, target: str) -> str:
        """Detect the type of target based on input"""
        path = Path(target)
        
        if path.exists() and path.is_dir():
            return 'codebase'
        elif target.startswith('0x') and len(target) == 42:
            return 'contract'
        else:
            return 'protocol'
    
    def _generate_exploit_id(self) -> str:
        """Generate unique exploit ID"""
        import hashlib
        timestamp = datetime.now().isoformat()
        return hashlib.sha256(timestamp.encode()).hexdigest()[:16]
    
    def _calculate_severity(
        self,
        execution_result: Dict[str, Any],
        validation: Dict[str, Any]
    ) -> str:
        """Calculate exploit severity based on impact and likelihood"""
        funds_at_risk = validation.get('funds_at_risk', 0)
        confidence = validation.get('confidence', 0)
        
        if funds_at_risk > 1000000 or confidence > 0.9:
            return 'critical'
        elif funds_at_risk > 100000 or confidence > 0.7:
            return 'high'
        elif funds_at_risk > 10000 or confidence > 0.5:
            return 'medium'
        else:
            return 'low'
    
    def _get_market_state(self) -> MarketState:
        """Get current market state"""
        # This would fetch real market data
        # Simplified for demonstration
        return MarketState(
            block_number=1000000,
            timestamp=1234567890,
            prices={
                'uniswap': {'ETH_USDC': 2000, 'ETH_DAI': 2001},
                'sushiswap': {'ETH_USDC': 1999, 'ETH_DAI': 2000}
            },
            base_fee=30.0,
            priority_fee=2.0
        )
    
    async def analyze_protocol(
        self,
        protocol_path: str,
        deep_analysis: bool = True
    ) -> Dict[str, Any]:
        """Analyze a complete protocol for vulnerabilities"""
        logger.info(f"Analyzing protocol at {protocol_path}")
        
        # Comprehensive protocol analysis
        exploits = await self.discover_exploits(
            protocol_path,
            target_type='protocol',
            context={'deep_analysis': deep_analysis}
        )
        
        return {
            'protocol': protocol_path,
            'exploits': exploits,
            'total_found': len(exploits),
            'critical': len([e for e in exploits if e.severity == 'critical']),
            'high': len([e for e in exploits if e.severity == 'high']),
            'medium': len([e for e in exploits if e.severity == 'medium']),
            'low': len([e for e in exploits if e.severity == 'low'])
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about discovered exploits"""
        return {
            'total_exploits': len(self.discovered_exploits),
            'by_severity': {
                'critical': len([e for e in self.discovered_exploits if e.severity == 'critical']),
                'high': len([e for e in self.discovered_exploits if e.severity == 'high']),
                'medium': len([e for e in self.discovered_exploits if e.severity == 'medium']),
                'low': len([e for e in self.discovered_exploits if e.severity == 'low'])
            },
            'by_type': self._group_by_type(),
            'total_funds_at_risk': sum(e.funds_at_risk or 0 for e in self.discovered_exploits),
            'analysis_count': len(self.analysis_history)
        }
    
    def _group_by_type(self) -> Dict[str, int]:
        """Group exploits by vulnerability type"""
        type_counts = {}
        for exploit in self.discovered_exploits:
            vuln_type = exploit.vulnerability_type
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
        return type_counts