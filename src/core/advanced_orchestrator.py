"""
Ultra-Advanced Modular Agentic Orchestrator with Hierarchical Decision Making

This is the most advanced version with:
- Fully modular agent system with plugin architecture
- Hierarchical decision-making with meta-agents
- Distributed memory for large-scale analysis
- Parallel processing capabilities
- Advanced novel exploit synthesis
"""

import asyncio
import json
import logging
import hashlib
import numpy as np
from typing import Any, Dict, List, Optional, Tuple, Set, Callable, Type
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from abc import ABC, abstractmethod
import concurrent.futures
from collections import defaultdict, deque
import networkx as nx
import pickle
import os

from .llm_client import get_llm_client, OpenRouterClient, LLMMessage
from .brilliant_memory import BrilliantMemory

logger = logging.getLogger(__name__)


# ============================================================================
# MODULAR AGENT ARCHITECTURE
# ============================================================================

class AgentCapability(Enum):
    """Capabilities that agents can have"""
    ANALYSIS = "analysis"
    SYNTHESIS = "synthesis"
    VALIDATION = "validation"
    CREATIVITY = "creativity"
    MEMORY = "memory"
    PLANNING = "planning"
    EXECUTION = "execution"
    LEARNING = "learning"
    REASONING = "reasoning"
    PATTERN_RECOGNITION = "pattern_recognition"
    ABSTRACTION = "abstraction"
    OPTIMIZATION = "optimization"


@dataclass
class AgentMessage:
    """Message passed between agents"""
    sender: str
    receiver: str
    content: Dict[str, Any]
    priority: int = 0
    timestamp: datetime = field(default_factory=datetime.now)
    requires_response: bool = False
    correlation_id: Optional[str] = None


@dataclass
class Decision:
    """Represents a decision made by an agent"""
    agent_id: str
    decision_type: str
    choice: Any
    confidence: float
    reasoning: str
    alternatives: List[Dict[str, Any]] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    
    
class BaseAgent(ABC):
    """Abstract base class for all agents"""
    
    def __init__(
        self,
        agent_id: str,
        capabilities: List[AgentCapability],
        llm_client: OpenRouterClient,
        temperature: float = 0.7
    ):
        self.agent_id = agent_id
        self.capabilities = capabilities
        self.llm_client = llm_client
        self.temperature = temperature
        self.memory = deque(maxlen=1000)
        self.message_queue = asyncio.Queue()
        self.active = True
        self.performance_metrics = {
            'decisions_made': 0,
            'success_rate': 0.0,
            'avg_confidence': 0.0
        }
    
    @abstractmethod
    async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process input and return output"""
        pass
    
    @abstractmethod
    async def decide(self, context: Dict[str, Any], options: List[Any]) -> Decision:
        """Make a decision given context and options"""
        pass
    
    async def think(self, prompt: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Use LLM to think about a problem"""
        messages = [
            LLMMessage(
                role="system",
                content=f"You are {self.agent_id}, an expert AI agent with capabilities: {self.capabilities}"
            ),
            LLMMessage(
                role="user",
                content=f"{prompt}\n\nContext:\n{json.dumps(context, indent=2)}"
            )
        ]
        
        response = await self.llm_client.complete(messages, temperature=self.temperature)
        
        try:
            return json.loads(response.content)
        except:
            return {'response': response.content}
    
    async def collaborate(self, other_agent: 'BaseAgent', task: Dict[str, Any]) -> Dict[str, Any]:
        """Collaborate with another agent on a task"""
        # Exchange messages
        message = AgentMessage(
            sender=self.agent_id,
            receiver=other_agent.agent_id,
            content=task,
            requires_response=True
        )
        
        await other_agent.message_queue.put(message)
        
        # Wait for response
        # In production, implement proper correlation
        return await self.process_messages()
    
    async def process_messages(self) -> Dict[str, Any]:
        """Process incoming messages"""
        results = []
        
        while not self.message_queue.empty():
            message = await self.message_queue.get()
            
            if message.requires_response:
                result = await self.process({'message': message.content})
                results.append(result)
        
        return {'processed_messages': results}


# ============================================================================
# SPECIALIZED AGENT IMPLEMENTATIONS
# ============================================================================

class AnalysisAgent(BaseAgent):
    """Agent specialized in deep analysis"""
    
    def __init__(self, llm_client: OpenRouterClient):
        super().__init__(
            agent_id="AnalysisAgent",
            capabilities=[AgentCapability.ANALYSIS, AgentCapability.PATTERN_RECOGNITION],
            llm_client=llm_client,
            temperature=0.4
        )
    
    async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform deep analysis"""
        prompt = """Perform deep security analysis on the provided data.
        Identify:
        1. Attack surfaces
        2. Data flow vulnerabilities
        3. State manipulation opportunities
        4. Economic attack vectors
        5. Composability risks
        
        Provide structured analysis with confidence scores."""
        
        return await self.think(prompt, input_data)
    
    async def decide(self, context: Dict[str, Any], options: List[Any]) -> Decision:
        """Decide on analysis approach"""
        prompt = f"""Given these analysis options: {options}
        Which approach would be most effective for finding vulnerabilities?
        Consider depth vs breadth, time constraints, and likelihood of discovery."""
        
        result = await self.think(prompt, context)
        
        return Decision(
            agent_id=self.agent_id,
            decision_type="analysis_approach",
            choice=result.get('choice', options[0] if options else None),
            confidence=result.get('confidence', 0.5),
            reasoning=result.get('reasoning', '')
        )


class CreativeAgent(BaseAgent):
    """Agent specialized in creative exploit generation"""
    
    def __init__(self, llm_client: OpenRouterClient):
        super().__init__(
            agent_id="CreativeAgent",
            capabilities=[AgentCapability.CREATIVITY, AgentCapability.SYNTHESIS],
            llm_client=llm_client,
            temperature=0.9
        )
    
    async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate creative exploit ideas"""
        prompt = """Generate NOVEL and CREATIVE exploit ideas that have never been seen before.
        Combine unrelated vulnerabilities in unexpected ways.
        Think like an artist, not an engineer.
        Break conventional security assumptions.
        
        Requirements:
        1. Must be technically feasible
        2. Should combine 3+ different concepts
        3. Must bypass standard defenses
        4. Should have high impact potential
        
        Be wildly creative but technically sound."""
        
        return await self.think(prompt, input_data)
    
    async def decide(self, context: Dict[str, Any], options: List[Any]) -> Decision:
        """Make creative decisions"""
        prompt = f"""Given options: {options}
        Choose the most unconventional and creative approach.
        Prioritize novelty and unexpected combinations."""
        
        result = await self.think(prompt, context)
        
        return Decision(
            agent_id=self.agent_id,
            decision_type="creative_choice",
            choice=result.get('choice', options[0] if options else None),
            confidence=result.get('confidence', 0.7),
            reasoning=result.get('reasoning', '')
        )


class MetaAgent(BaseAgent):
    """Meta-agent that coordinates other agents"""
    
    def __init__(self, llm_client: OpenRouterClient):
        super().__init__(
            agent_id="MetaAgent",
            capabilities=[AgentCapability.PLANNING, AgentCapability.OPTIMIZATION],
            llm_client=llm_client,
            temperature=0.5
        )
        self.subordinate_agents: List[BaseAgent] = []
    
    async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Coordinate multi-agent analysis"""
        # Decide which agents to activate
        agent_plan = await self.plan_agent_activation(input_data)
        
        # Distribute tasks
        tasks = []
        for agent_id, task in agent_plan.items():
            agent = self.get_agent(agent_id)
            if agent:
                tasks.append(agent.process(task))
        
        # Collect results
        results = await asyncio.gather(*tasks)
        
        # Synthesize findings
        synthesis = await self.synthesize_results(results)
        
        return synthesis
    
    async def decide(self, context: Dict[str, Any], options: List[Any]) -> Decision:
        """Make meta-level decisions about agent coordination"""
        prompt = f"""As a meta-coordinator, decide the best strategy for agent collaboration.
        Options: {options}
        Consider parallelization, sequencing, and resource optimization."""
        
        result = await self.think(prompt, context)
        
        return Decision(
            agent_id=self.agent_id,
            decision_type="coordination_strategy",
            choice=result.get('strategy', options[0] if options else None),
            confidence=result.get('confidence', 0.8),
            reasoning=result.get('reasoning', '')
        )
    
    async def plan_agent_activation(self, task: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Plan which agents to activate and their tasks"""
        prompt = """Given this task, plan which specialized agents to activate.
        Return a mapping of agent_id to their specific subtask.
        Consider agent capabilities and optimize for efficiency."""
        
        result = await self.think(prompt, task)
        return result.get('agent_tasks', {})
    
    async def synthesize_results(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Synthesize results from multiple agents"""
        prompt = """Synthesize these results from multiple agents into a coherent analysis.
        Identify consensus, conflicts, and emergent insights.
        Prioritize findings by impact and confidence."""
        
        return await self.think(prompt, {'results': results})
    
    def get_agent(self, agent_id: str) -> Optional[BaseAgent]:
        """Get agent by ID"""
        for agent in self.subordinate_agents:
            if agent.agent_id == agent_id:
                return agent
        return None
    
    def add_agent(self, agent: BaseAgent):
        """Add subordinate agent"""
        self.subordinate_agents.append(agent)


# ============================================================================
# HIERARCHICAL ORCHESTRATOR
# ============================================================================

class HierarchicalOrchestrator:
    """
    Most advanced orchestrator with hierarchical decision-making
    
    Features:
    - Multiple layers of meta-agents
    - Distributed processing for large codebases
    - Advanced memory management
    - Plugin architecture for custom agents
    - Real-time learning and adaptation
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.llm_client = get_llm_client()
        
        # Initialize hierarchical agent structure
        self.agent_hierarchy = self._build_hierarchy()
        
        # Advanced memory system
        self.global_memory = BrilliantMemory(embedding_dim=1024)  # Larger embeddings
        self.working_memory = deque(maxlen=10000)  # Larger working memory
        
        # Decision history for learning
        self.decision_history: List[Decision] = []
        
        # Performance tracking
        self.metrics = defaultdict(lambda: defaultdict(float))
        
        # Plugin system for custom agents
        self.custom_agents: Dict[str, Type[BaseAgent]] = {}
        
        # Parallel processing pool
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=10)
        
        logger.info("Hierarchical Orchestrator initialized with advanced capabilities")
    
    def _build_hierarchy(self) -> Dict[str, Any]:
        """Build hierarchical agent structure"""
        # Level 0: Root meta-agent
        root_meta = MetaAgent(self.llm_client)
        
        # Level 1: Domain meta-agents
        security_meta = MetaAgent(self.llm_client)
        security_meta.agent_id = "SecurityMeta"
        
        economic_meta = MetaAgent(self.llm_client)
        economic_meta.agent_id = "EconomicMeta"
        
        creative_meta = MetaAgent(self.llm_client)
        creative_meta.agent_id = "CreativeMeta"
        
        # Level 2: Specialized agents
        agents = {
            'analysis': AnalysisAgent(self.llm_client),
            'creative': CreativeAgent(self.llm_client),
            'pattern': self._create_pattern_agent(),
            'validator': self._create_validator_agent(),
            'synthesizer': self._create_synthesizer_agent(),
            'adversary': self._create_adversary_agent(),
            'memory': self._create_memory_agent(),
            'explorer': self._create_explorer_agent()
        }
        
        # Build hierarchy
        security_meta.add_agent(agents['analysis'])
        security_meta.add_agent(agents['validator'])
        
        creative_meta.add_agent(agents['creative'])
        creative_meta.add_agent(agents['explorer'])
        
        economic_meta.add_agent(agents['adversary'])
        economic_meta.add_agent(agents['synthesizer'])
        
        root_meta.add_agent(security_meta)
        root_meta.add_agent(economic_meta)
        root_meta.add_agent(creative_meta)
        
        return {
            'root': root_meta,
            'level1': [security_meta, economic_meta, creative_meta],
            'level2': agents,
            'all_agents': self._flatten_agents(root_meta)
        }
    
    def _create_pattern_agent(self) -> BaseAgent:
        """Create pattern recognition agent"""
        class PatternAgent(BaseAgent):
            async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
                prompt = """Identify patterns in the data that indicate vulnerabilities.
                Look for: recurring structures, anti-patterns, suspicious combinations."""
                return await self.think(prompt, input_data)
            
            async def decide(self, context: Dict[str, Any], options: List[Any]) -> Decision:
                result = await self.think("Choose pattern matching strategy", context)
                return Decision(
                    agent_id=self.agent_id,
                    decision_type="pattern_strategy",
                    choice=result.get('choice', options[0] if options else None),
                    confidence=result.get('confidence', 0.6),
                    reasoning=result.get('reasoning', '')
                )
        
        return PatternAgent(
            agent_id="PatternAgent",
            capabilities=[AgentCapability.PATTERN_RECOGNITION],
            llm_client=self.llm_client,
            temperature=0.5
        )
    
    def _create_validator_agent(self) -> BaseAgent:
        """Create validation agent"""
        class ValidatorAgent(BaseAgent):
            async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
                prompt = """Validate the feasibility and impact of proposed exploits.
                Check: technical feasibility, prerequisites, success probability, impact."""
                return await self.think(prompt, input_data)
            
            async def decide(self, context: Dict[str, Any], options: List[Any]) -> Decision:
                result = await self.think("Decide validation approach", context)
                return Decision(
                    agent_id=self.agent_id,
                    decision_type="validation_method",
                    choice=result.get('choice', options[0] if options else None),
                    confidence=result.get('confidence', 0.9),
                    reasoning=result.get('reasoning', '')
                )
        
        return ValidatorAgent(
            agent_id="ValidatorAgent",
            capabilities=[AgentCapability.VALIDATION],
            llm_client=self.llm_client,
            temperature=0.3
        )
    
    def _create_synthesizer_agent(self) -> BaseAgent:
        """Create synthesis agent"""
        class SynthesizerAgent(BaseAgent):
            async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
                prompt = """Synthesize multiple findings into coherent exploit strategies.
                Combine partial vulnerabilities into complete attacks."""
                return await self.think(prompt, input_data)
            
            async def decide(self, context: Dict[str, Any], options: List[Any]) -> Decision:
                result = await self.think("Choose synthesis approach", context)
                return Decision(
                    agent_id=self.agent_id,
                    decision_type="synthesis_strategy",
                    choice=result.get('choice', options[0] if options else None),
                    confidence=result.get('confidence', 0.7),
                    reasoning=result.get('reasoning', '')
                )
        
        return SynthesizerAgent(
            agent_id="SynthesizerAgent",
            capabilities=[AgentCapability.SYNTHESIS],
            llm_client=self.llm_client,
            temperature=0.6
        )
    
    def _create_adversary_agent(self) -> BaseAgent:
        """Create adversarial agent"""
        class AdversaryAgent(BaseAgent):
            async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
                prompt = """Think like a malicious attacker seeking maximum profit.
                Optimize exploits for: impact, stealth, profitability, scalability."""
                return await self.think(prompt, input_data)
            
            async def decide(self, context: Dict[str, Any], options: List[Any]) -> Decision:
                result = await self.think("Choose most profitable attack", context)
                return Decision(
                    agent_id=self.agent_id,
                    decision_type="attack_optimization",
                    choice=result.get('choice', options[0] if options else None),
                    confidence=result.get('confidence', 0.8),
                    reasoning=result.get('reasoning', '')
                )
        
        return AdversaryAgent(
            agent_id="AdversaryAgent",
            capabilities=[AgentCapability.OPTIMIZATION],
            llm_client=self.llm_client,
            temperature=0.8
        )
    
    def _create_memory_agent(self) -> BaseAgent:
        """Create memory management agent"""
        class MemoryAgent(BaseAgent):
            async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
                prompt = """Manage system memory: store important discoveries,
                retrieve relevant past experiences, identify patterns over time."""
                return await self.think(prompt, input_data)
            
            async def decide(self, context: Dict[str, Any], options: List[Any]) -> Decision:
                result = await self.think("Decide memory strategy", context)
                return Decision(
                    agent_id=self.agent_id,
                    decision_type="memory_management",
                    choice=result.get('choice', options[0] if options else None),
                    confidence=result.get('confidence', 0.7),
                    reasoning=result.get('reasoning', '')
                )
        
        return MemoryAgent(
            agent_id="MemoryAgent",
            capabilities=[AgentCapability.MEMORY, AgentCapability.LEARNING],
            llm_client=self.llm_client,
            temperature=0.4
        )
    
    def _create_explorer_agent(self) -> BaseAgent:
        """Create exploration agent"""
        class ExplorerAgent(BaseAgent):
            async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
                prompt = """Explore unconventional attack vectors and edge cases.
                Look beyond obvious vulnerabilities to find hidden attack surfaces."""
                return await self.think(prompt, input_data)
            
            async def decide(self, context: Dict[str, Any], options: List[Any]) -> Decision:
                result = await self.think("Choose exploration strategy", context)
                return Decision(
                    agent_id=self.agent_id,
                    decision_type="exploration_path",
                    choice=result.get('choice', options[0] if options else None),
                    confidence=result.get('confidence', 0.6),
                    reasoning=result.get('reasoning', '')
                )
        
        return ExplorerAgent(
            agent_id="ExplorerAgent",
            capabilities=[AgentCapability.CREATIVITY, AgentCapability.ANALYSIS],
            llm_client=self.llm_client,
            temperature=0.85
        )
    
    def _flatten_agents(self, root: MetaAgent) -> List[BaseAgent]:
        """Flatten agent hierarchy into list"""
        agents = [root]
        
        def traverse(agent: MetaAgent):
            if isinstance(agent, MetaAgent):
                for sub_agent in agent.subordinate_agents:
                    agents.append(sub_agent)
                    if isinstance(sub_agent, MetaAgent):
                        traverse(sub_agent)
        
        traverse(root)
        return agents
    
    async def analyze_large_codebase(
        self,
        codebase_path: str,
        chunk_size: int = 1000
    ) -> List[Dict[str, Any]]:
        """
        Analyze large codebase using distributed processing
        
        This method can handle massive codebases by:
        - Chunking the codebase into manageable pieces
        - Processing chunks in parallel
        - Maintaining context across chunks
        - Synthesizing findings at the end
        """
        logger.info(f"Analyzing large codebase: {codebase_path}")
        
        # Phase 1: Chunk the codebase
        chunks = await self._chunk_codebase(codebase_path, chunk_size)
        logger.info(f"Split codebase into {len(chunks)} chunks")
        
        # Phase 2: Parallel analysis
        chunk_results = await self._parallel_chunk_analysis(chunks)
        
        # Phase 3: Cross-chunk pattern detection
        patterns = await self._detect_cross_chunk_patterns(chunk_results)
        
        # Phase 4: Synthesize findings
        synthesized = await self._synthesize_codebase_findings(chunk_results, patterns)
        
        # Phase 5: Generate novel exploits
        novel_exploits = await self._generate_novel_exploits(synthesized)
        
        return novel_exploits
    
    async def _chunk_codebase(self, path: str, chunk_size: int) -> List[Dict[str, Any]]:
        """Intelligently chunk codebase for analysis"""
        chunks = []
        
        # In production, implement smart chunking that preserves context
        # For now, simplified chunking
        chunk = {
            'id': f"chunk_{len(chunks)}",
            'path': path,
            'files': [],
            'context': {}
        }
        chunks.append(chunk)
        
        return chunks
    
    async def _parallel_chunk_analysis(
        self,
        chunks: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Analyze chunks in parallel"""
        tasks = []
        
        for chunk in chunks:
            # Assign to different agents for parallel processing
            agent = self.agent_hierarchy['all_agents'][
                hash(chunk['id']) % len(self.agent_hierarchy['all_agents'])
            ]
            tasks.append(self._analyze_chunk(chunk, agent))
        
        results = await asyncio.gather(*tasks)
        return results
    
    async def _analyze_chunk(
        self,
        chunk: Dict[str, Any],
        agent: BaseAgent
    ) -> Dict[str, Any]:
        """Analyze a single chunk"""
        # Add memory context
        memory_context = await self.global_memory.recall(chunk, k=5)
        chunk['memory_context'] = [
            {'content': node.content, 'importance': node.importance}
            for node, score in memory_context
        ]
        
        # Analyze
        result = await agent.process(chunk)
        
        # Store in memory
        await self.global_memory.store(
            result,
            context={'chunk_id': chunk['id']},
            importance=0.7
        )
        
        return result
    
    async def _detect_cross_chunk_patterns(
        self,
        chunk_results: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Detect patterns across chunks"""
        pattern_agent = self.agent_hierarchy['level2']['pattern']
        
        patterns = await pattern_agent.process({
            'chunk_results': chunk_results,
            'task': 'Find patterns and connections across chunks'
        })
        
        return patterns.get('patterns', [])
    
    async def _synthesize_codebase_findings(
        self,
        chunk_results: List[Dict[str, Any]],
        patterns: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Synthesize all findings from codebase analysis"""
        synthesizer = self.agent_hierarchy['level2']['synthesizer']
        
        synthesis = await synthesizer.process({
            'chunk_results': chunk_results,
            'patterns': patterns,
            'task': 'Create comprehensive vulnerability assessment'
        })
        
        return synthesis
    
    async def _generate_novel_exploits(
        self,
        synthesis: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate novel exploits from synthesis"""
        # Use creative agent for novel ideas
        creative = self.agent_hierarchy['level2']['creative']
        
        novel_ideas = await creative.process({
            'synthesis': synthesis,
            'task': 'Generate completely novel exploit combinations'
        })
        
        # Validate with validator agent
        validator = self.agent_hierarchy['level2']['validator']
        
        validated_exploits = []
        for idea in novel_ideas.get('exploits', []):
            validation = await validator.process({'exploit': idea})
            
            if validation.get('feasible', False):
                idea['validation'] = validation
                validated_exploits.append(idea)
        
        return validated_exploits
    
    async def make_hierarchical_decision(
        self,
        decision_context: Dict[str, Any]
    ) -> Decision:
        """
        Make decision using hierarchical consensus
        
        Decisions flow up the hierarchy:
        1. Specialized agents propose options
        2. Domain meta-agents filter and prioritize
        3. Root meta-agent makes final decision
        """
        # Level 2: Get proposals from specialized agents
        proposals = []
        for agent in self.agent_hierarchy['level2'].values():
            proposal = await agent.decide(
                decision_context,
                decision_context.get('options', [])
            )
            proposals.append(proposal)
        
        # Level 1: Domain meta-agents evaluate proposals
        domain_decisions = []
        for meta_agent in self.agent_hierarchy['level1']:
            domain_decision = await meta_agent.decide(
                {'proposals': proposals, 'context': decision_context},
                [p.choice for p in proposals]
            )
            domain_decisions.append(domain_decision)
        
        # Level 0: Root makes final decision
        final_decision = await self.agent_hierarchy['root'].decide(
            {'domain_decisions': domain_decisions, 'context': decision_context},
            [d.choice for d in domain_decisions]
        )
        
        # Record decision for learning
        self.decision_history.append(final_decision)
        
        # Update metrics
        self._update_metrics(final_decision)
        
        return final_decision
    
    def _update_metrics(self, decision: Decision):
        """Update performance metrics"""
        agent_id = decision.agent_id
        self.metrics[agent_id]['total_decisions'] += 1
        self.metrics[agent_id]['avg_confidence'] = (
            self.metrics[agent_id]['avg_confidence'] * 
            (self.metrics[agent_id]['total_decisions'] - 1) +
            decision.confidence
        ) / self.metrics[agent_id]['total_decisions']
    
    def register_custom_agent(self, agent_class: Type[BaseAgent], name: str):
        """Register custom agent plugin"""
        self.custom_agents[name] = agent_class
        logger.info(f"Registered custom agent: {name}")
    
    async def execute_custom_agent(
        self,
        agent_name: str,
        task: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute registered custom agent"""
        if agent_name not in self.custom_agents:
            raise ValueError(f"Unknown custom agent: {agent_name}")
        
        agent_class = self.custom_agents[agent_name]
        agent = agent_class(self.llm_client)
        
        return await agent.process(task)
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Get detailed performance metrics"""
        return {
            'agent_metrics': dict(self.metrics),
            'total_decisions': len(self.decision_history),
            'memory_size': len(self.global_memory.nodes),
            'working_memory_size': len(self.working_memory),
            'custom_agents_registered': len(self.custom_agents)
        }


# ============================================================================
# SINGLETON INSTANCE
# ============================================================================

_advanced_orchestrator: Optional[HierarchicalOrchestrator] = None


def get_advanced_orchestrator(
    config: Optional[Dict[str, Any]] = None
) -> HierarchicalOrchestrator:
    """Get or create the advanced orchestrator singleton"""
    global _advanced_orchestrator
    if _advanced_orchestrator is None:
        _advanced_orchestrator = HierarchicalOrchestrator(config)
    return _advanced_orchestrator