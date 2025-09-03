"""
Advanced Agentic Orchestrator - Fully LLM-Driven Exploit Discovery System

This module implements a sophisticated multi-agent system where LLMs make all
critical decisions, learn from discoveries, and autonomously find novel exploits
through creative reasoning and brilliant memory.
"""

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import hashlib
import numpy as np
from collections import deque
import pickle
import os

from .llm_client import get_llm_client, OpenRouterClient, LLMMessage

logger = logging.getLogger(__name__)


class AgentRole(Enum):
    """Specialized roles for different agents in the system"""
    STRATEGIST = "strategist"          # High-level attack strategy planning
    RESEARCHER = "researcher"          # Deep vulnerability research
    EXPLORER = "explorer"              # Novel attack vector discovery
    VALIDATOR = "validator"            # Exploit validation and verification
    SYNTHESIZER = "synthesizer"        # Combines insights from multiple agents
    MEMORY_KEEPER = "memory_keeper"    # Manages system memory and learning
    CREATIVE = "creative"              # Generates unconventional approaches
    ADVERSARY = "adversary"            # Simulates attacker mindset


@dataclass
class AgentMemory:
    """Brilliant memory system for storing and retrieving exploit knowledge"""
    short_term: deque = field(default_factory=lambda: deque(maxlen=100))
    long_term: Dict[str, Any] = field(default_factory=dict)
    episodic: List[Dict[str, Any]] = field(default_factory=list)
    semantic: Dict[str, List[Any]] = field(default_factory=dict)
    embeddings: Dict[str, np.ndarray] = field(default_factory=dict)
    
    def store_discovery(self, discovery: Dict[str, Any]):
        """Store a new discovery in memory with embeddings"""
        discovery_id = hashlib.sha256(json.dumps(discovery, sort_keys=True).encode()).hexdigest()[:16]
        
        # Store in different memory types
        self.short_term.append(discovery)
        self.long_term[discovery_id] = discovery
        
        # Create episodic memory
        episode = {
            'id': discovery_id,
            'timestamp': datetime.now().isoformat(),
            'discovery': discovery,
            'context': discovery.get('context', {}),
            'success_rate': discovery.get('confidence', 0.0)
        }
        self.episodic.append(episode)
        
        # Update semantic memory
        vuln_type = discovery.get('vulnerability_type', 'unknown')
        if vuln_type not in self.semantic:
            self.semantic[vuln_type] = []
        self.semantic[vuln_type].append(discovery)
        
        # Generate embedding (simplified - in production use real embeddings)
        self.embeddings[discovery_id] = self._generate_embedding(discovery)
    
    def _generate_embedding(self, data: Dict[str, Any]) -> np.ndarray:
        """Generate embedding for similarity search"""
        # Simplified embedding - in production use sentence transformers or OpenAI embeddings
        text = json.dumps(data)
        return np.random.randn(768)  # 768-dim embedding
    
    def retrieve_similar(self, query: Dict[str, Any], top_k: int = 5) -> List[Dict[str, Any]]:
        """Retrieve similar discoveries using embeddings"""
        query_embedding = self._generate_embedding(query)
        
        similarities = []
        for disc_id, embedding in self.embeddings.items():
            similarity = np.dot(query_embedding, embedding) / (np.linalg.norm(query_embedding) * np.linalg.norm(embedding))
            similarities.append((disc_id, similarity))
        
        similarities.sort(key=lambda x: x[1], reverse=True)
        
        results = []
        for disc_id, score in similarities[:top_k]:
            if disc_id in self.long_term:
                results.append({
                    'discovery': self.long_term[disc_id],
                    'similarity': score
                })
        
        return results
    
    def get_insights(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Extract insights from memory based on context"""
        insights = {
            'patterns': [],
            'successful_strategies': [],
            'failed_attempts': [],
            'novel_approaches': []
        }
        
        # Analyze episodic memory for patterns
        for episode in self.episodic[-50:]:  # Last 50 episodes
            if episode['success_rate'] > 0.8:
                insights['successful_strategies'].append(episode['discovery'])
            elif episode['success_rate'] < 0.3:
                insights['failed_attempts'].append(episode['discovery'])
        
        # Find patterns in semantic memory
        for vuln_type, discoveries in self.semantic.items():
            if len(discoveries) > 3:
                insights['patterns'].append({
                    'type': vuln_type,
                    'frequency': len(discoveries),
                    'avg_confidence': sum(d.get('confidence', 0) for d in discoveries) / len(discoveries)
                })
        
        return insights


@dataclass
class Agent:
    """Autonomous agent with specific role and capabilities"""
    role: AgentRole
    llm_client: OpenRouterClient
    memory: AgentMemory
    temperature: float = 0.7
    
    async def think(self, context: Dict[str, Any], objective: str) -> Dict[str, Any]:
        """Agent's thinking process - fully LLM driven"""
        # Retrieve relevant memories
        memory_context = self.memory.get_insights(context)
        similar_cases = self.memory.retrieve_similar(context, top_k=3)
        
        system_prompt = self._get_system_prompt()
        
        user_prompt = f"""
Objective: {objective}

Current Context:
{json.dumps(context, indent=2)}

Memory Insights:
{json.dumps(memory_context, indent=2)}

Similar Previous Cases:
{json.dumps(similar_cases, indent=2)}

Based on your role as {self.role.value}, provide your analysis and recommendations.
Include:
1. Key observations
2. Potential vulnerabilities or attack vectors
3. Novel approaches not seen before
4. Confidence level (0-1)
5. Recommended next steps

Format as JSON.
"""
        
        messages = [
            LLMMessage(role="system", content=system_prompt),
            LLMMessage(role="user", content=user_prompt)
        ]
        
        response = await self.llm_client.complete(messages, temperature=self.temperature)
        
        try:
            thoughts = json.loads(response.content)
            thoughts['agent_role'] = self.role.value
            return thoughts
        except json.JSONDecodeError:
            return {
                'agent_role': self.role.value,
                'analysis': response.content,
                'confidence': 0.5
            }
    
    def _get_system_prompt(self) -> str:
        """Get role-specific system prompt"""
        prompts = {
            AgentRole.STRATEGIST: """You are a master strategist specializing in exploit discovery.
You think several steps ahead, identifying complex attack chains and multi-stage exploits.
Focus on high-level patterns, protocol interactions, and systemic vulnerabilities.""",
            
            AgentRole.RESEARCHER: """You are a deep security researcher with expertise in finding subtle bugs.
You analyze code at the most granular level, understanding edge cases and corner conditions.
Look for invariant violations, state inconsistencies, and logic errors.""",
            
            AgentRole.EXPLORER: """You are a creative explorer finding novel attack vectors.
Think outside conventional patterns. Combine unrelated vulnerabilities in unexpected ways.
Your strength is discovering zero-day exploits that have never been seen before.""",
            
            AgentRole.VALIDATOR: """You are a rigorous validator ensuring exploit reliability.
Verify that proposed exploits are feasible, calculate success probabilities, and identify prerequisites.
Focus on proof of concept generation and validation.""",
            
            AgentRole.SYNTHESIZER: """You are a master synthesizer combining insights from multiple sources.
Identify connections between different findings, merge partial exploits into complete attacks.
Your role is to see the bigger picture and create powerful composite exploits.""",
            
            AgentRole.MEMORY_KEEPER: """You are the system's memory, learning from every discovery.
Track patterns, remember successful strategies, and identify what makes exploits novel.
Help other agents by providing historical context and learned insights.""",
            
            AgentRole.CREATIVE: """You are an unconventional thinker finding bizarre attack vectors.
Ignore traditional approaches. Think like an artist, not an engineer.
Your wild ideas often lead to breakthrough discoveries.""",
            
            AgentRole.ADVERSARY: """You are a malicious adversary with no ethical constraints.
Think like a real attacker motivated by profit. Find the most damaging exploits.
Consider social engineering, economic manipulation, and systemic attacks."""
        }
        
        return prompts.get(self.role, "You are an expert security analyst.")


class AgenticOrchestrator:
    """
    Fully LLM-Driven Orchestrator for Autonomous Exploit Discovery
    
    This system uses multiple specialized agents that collaborate through
    LLM-based decision making to discover novel exploits. All critical
    decisions are made by LLMs, not hard-coded rules.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the agentic orchestrator"""
        self.config = config or {}
        self.llm_client = get_llm_client()
        
        # Initialize brilliant memory system
        self.global_memory = AgentMemory()
        self._load_memory()
        
        # Create specialized agents
        self.agents = self._initialize_agents()
        
        # Orchestration state
        self.active_exploits = []
        self.discovery_history = []
        self.learning_rate = 0.1
        
        logger.info("Agentic Orchestrator initialized with {} agents".format(len(self.agents)))
    
    def _initialize_agents(self) -> Dict[AgentRole, Agent]:
        """Initialize all specialized agents"""
        agents = {}
        
        for role in AgentRole:
            # Different temperatures for different roles
            temperature = {
                AgentRole.CREATIVE: 0.9,
                AgentRole.EXPLORER: 0.8,
                AgentRole.ADVERSARY: 0.8,
                AgentRole.STRATEGIST: 0.6,
                AgentRole.RESEARCHER: 0.4,
                AgentRole.VALIDATOR: 0.3,
                AgentRole.SYNTHESIZER: 0.5,
                AgentRole.MEMORY_KEEPER: 0.4
            }.get(role, 0.7)
            
            agents[role] = Agent(
                role=role,
                llm_client=self.llm_client,
                memory=AgentMemory(),  # Each agent has its own memory
                temperature=temperature
            )
        
        return agents
    
    async def discover_novel_exploits(
        self,
        target: str,
        context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Main entry point for novel exploit discovery
        
        This method orchestrates multiple agents to collaboratively
        discover new and creative exploits using LLM reasoning.
        """
        logger.info(f"Starting novel exploit discovery for {target}")
        
        # Phase 1: Initial Analysis by Multiple Agents
        initial_thoughts = await self._parallel_agent_analysis(target, context)
        
        # Phase 2: LLM-Driven Synthesis
        synthesized_insights = await self._synthesize_insights(initial_thoughts)
        
        # Phase 3: Creative Exploration
        novel_approaches = await self._explore_novel_vectors(synthesized_insights, context)
        
        # Phase 4: Adversarial Enhancement
        adversarial_exploits = await self._adversarial_thinking(novel_approaches)
        
        # Phase 5: Validation and Refinement
        validated_exploits = await self._validate_exploits(adversarial_exploits)
        
        # Phase 6: Memory Integration and Learning
        await self._integrate_discoveries(validated_exploits)
        
        # Phase 7: Generate Proof of Concepts
        final_exploits = await self._generate_pocs(validated_exploits)
        
        return final_exploits
    
    async def _parallel_agent_analysis(
        self,
        target: str,
        context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Have multiple agents analyze the target in parallel"""
        tasks = []
        
        # Each agent analyzes from their perspective
        for role in [AgentRole.STRATEGIST, AgentRole.RESEARCHER, AgentRole.EXPLORER]:
            agent = self.agents[role]
            objective = f"Analyze {target} for vulnerabilities from your perspective"
            tasks.append(agent.think(context, objective))
        
        thoughts = await asyncio.gather(*tasks)
        return thoughts
    
    async def _synthesize_insights(
        self,
        thoughts: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Use synthesizer agent to combine insights"""
        synthesizer = self.agents[AgentRole.SYNTHESIZER]
        
        context = {
            'agent_thoughts': thoughts,
            'thought_count': len(thoughts)
        }
        
        objective = "Synthesize all agent insights into coherent attack strategies"
        synthesis = await synthesizer.think(context, objective)
        
        return synthesis
    
    async def _explore_novel_vectors(
        self,
        synthesis: Dict[str, Any],
        original_context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Use creative and explorer agents to find novel approaches"""
        creative = self.agents[AgentRole.CREATIVE]
        explorer = self.agents[AgentRole.EXPLORER]
        
        # Get memory insights for novelty
        memory_keeper = self.agents[AgentRole.MEMORY_KEEPER]
        memory_insights = await memory_keeper.think(
            {'synthesis': synthesis},
            "What patterns have we NOT seen before? What would be truly novel?"
        )
        
        # Creative agent generates wild ideas
        creative_ideas = await creative.think(
            {
                'synthesis': synthesis,
                'memory_insights': memory_insights,
                'context': original_context
            },
            "Generate unconventional attack vectors that combine multiple vulnerabilities in unexpected ways"
        )
        
        # Explorer agent explores the creative ideas
        exploration = await explorer.think(
            {
                'creative_ideas': creative_ideas,
                'synthesis': synthesis
            },
            "Explore the feasibility of creative attack vectors and discover new paths"
        )
        
        # Combine novel approaches
        novel_vectors = []
        
        if isinstance(creative_ideas.get('novel_approaches'), list):
            novel_vectors.extend(creative_ideas['novel_approaches'])
        
        if isinstance(exploration.get('discoveries'), list):
            novel_vectors.extend(exploration['discoveries'])
        
        return novel_vectors
    
    async def _adversarial_thinking(
        self,
        approaches: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Use adversarial agent to enhance exploits"""
        adversary = self.agents[AgentRole.ADVERSARY]
        
        enhanced_exploits = []
        
        for approach in approaches:
            adversarial_enhancement = await adversary.think(
                {'approach': approach},
                "How would a real attacker maximize damage with this vulnerability? Think profit and impact."
            )
            
            if 'enhanced_exploit' in adversarial_enhancement:
                enhanced_exploits.append(adversarial_enhancement['enhanced_exploit'])
            else:
                # Enhance the original approach with adversarial insights
                approach['adversarial_insights'] = adversarial_enhancement
                enhanced_exploits.append(approach)
        
        return enhanced_exploits
    
    async def _validate_exploits(
        self,
        exploits: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Use validator agent to verify exploits"""
        validator = self.agents[AgentRole.VALIDATOR]
        
        validated = []
        
        for exploit in exploits:
            validation = await validator.think(
                {'exploit': exploit},
                "Validate this exploit: check feasibility, prerequisites, and success probability"
            )
            
            confidence = validation.get('confidence', 0)
            if confidence > 0.6:  # Only keep high-confidence exploits
                exploit['validation'] = validation
                exploit['confidence'] = confidence
                validated.append(exploit)
        
        return validated
    
    async def _integrate_discoveries(
        self,
        exploits: List[Dict[str, Any]]
    ):
        """Integrate discoveries into memory for learning"""
        for exploit in exploits:
            # Store in global memory
            self.global_memory.store_discovery(exploit)
            
            # Update agent memories based on their contributions
            if 'agent_role' in exploit:
                role = AgentRole(exploit['agent_role'])
                if role in self.agents:
                    self.agents[role].memory.store_discovery(exploit)
        
        # Save memory to disk
        self._save_memory()
        
        # Trigger learning process
        await self._learn_from_discoveries(exploits)
    
    async def _learn_from_discoveries(
        self,
        exploits: List[Dict[str, Any]]
    ):
        """Learn from new discoveries to improve future performance"""
        memory_keeper = self.agents[AgentRole.MEMORY_KEEPER]
        
        learning_context = {
            'new_exploits': exploits,
            'total_discoveries': len(self.global_memory.long_term),
            'patterns': self.global_memory.get_insights({})['patterns']
        }
        
        learning_insights = await memory_keeper.think(
            learning_context,
            "What can we learn from these discoveries to improve our future exploit finding?"
        )
        
        # Store learning insights
        self.global_memory.semantic['learning_insights'] = \
            self.global_memory.semantic.get('learning_insights', []) + [learning_insights]
    
    async def _generate_pocs(
        self,
        exploits: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Generate proof of concepts for validated exploits"""
        for exploit in exploits:
            try:
                poc = await self.llm_client.generate_poc(exploit)
                exploit['poc'] = poc
            except Exception as e:
                logger.warning(f"Failed to generate PoC: {e}")
                exploit['poc'] = None
        
        return exploits
    
    def _save_memory(self):
        """Save memory to disk for persistence"""
        memory_path = self.config.get('memory_path', './data/agentic_memory.pkl')
        os.makedirs(os.path.dirname(memory_path), exist_ok=True)
        
        try:
            with open(memory_path, 'wb') as f:
                pickle.dump({
                    'global_memory': self.global_memory,
                    'agent_memories': {role: agent.memory for role, agent in self.agents.items()}
                }, f)
        except Exception as e:
            logger.error(f"Failed to save memory: {e}")
    
    def _load_memory(self):
        """Load memory from disk if available"""
        memory_path = self.config.get('memory_path', './data/agentic_memory.pkl')
        
        if os.path.exists(memory_path):
            try:
                with open(memory_path, 'rb') as f:
                    data = pickle.load(f)
                    self.global_memory = data.get('global_memory', AgentMemory())
                    logger.info(f"Loaded memory with {len(self.global_memory.long_term)} discoveries")
            except Exception as e:
                logger.warning(f"Failed to load memory: {e}")
    
    async def autonomous_discovery_loop(
        self,
        targets: List[str],
        max_iterations: int = 100
    ):
        """
        Fully autonomous discovery loop
        
        The system continuously discovers exploits, learns from them,
        and improves its capabilities over time.
        """
        logger.info(f"Starting autonomous discovery loop for {len(targets)} targets")
        
        for iteration in range(max_iterations):
            logger.info(f"Iteration {iteration + 1}/{max_iterations}")
            
            for target in targets:
                # Get current context from memory
                context = {
                    'iteration': iteration,
                    'previous_discoveries': len(self.discovery_history),
                    'memory_insights': self.global_memory.get_insights({})
                }
                
                # Discover exploits
                exploits = await self.discover_novel_exploits(target, context)
                
                # Add to history
                self.discovery_history.extend(exploits)
                
                # Log discoveries
                for exploit in exploits:
                    logger.info(f"Discovered: {exploit.get('type', 'unknown')} "
                              f"with confidence {exploit.get('confidence', 0):.2f}")
                
                # Adaptive learning - adjust agent temperatures based on success
                await self._adaptive_learning(exploits)
            
            # Periodic memory consolidation
            if iteration % 10 == 0:
                await self._consolidate_memory()
        
        logger.info(f"Autonomous discovery complete. Total exploits found: {len(self.discovery_history)}")
    
    async def _adaptive_learning(
        self,
        recent_exploits: List[Dict[str, Any]]
    ):
        """Adjust agent parameters based on performance"""
        if not recent_exploits:
            return
        
        # Calculate average confidence
        avg_confidence = sum(e.get('confidence', 0) for e in recent_exploits) / len(recent_exploits)
        
        # Adjust temperatures based on performance
        if avg_confidence > 0.8:
            # High success - can be more creative
            for agent in self.agents.values():
                agent.temperature = min(1.0, agent.temperature + 0.05)
        elif avg_confidence < 0.5:
            # Low success - be more conservative
            for agent in self.agents.values():
                agent.temperature = max(0.1, agent.temperature - 0.05)
    
    async def _consolidate_memory(self):
        """Consolidate and optimize memory"""
        # Remove low-value memories from short-term
        self.global_memory.short_term.clear()
        
        # Compress similar discoveries in long-term memory
        # This would involve clustering and deduplication
        logger.info(f"Memory consolidated. Long-term size: {len(self.global_memory.long_term)}")


# Singleton instance
_orchestrator_instance: Optional[AgenticOrchestrator] = None


def get_agentic_orchestrator(config: Optional[Dict[str, Any]] = None) -> AgenticOrchestrator:
    """Get or create the agentic orchestrator singleton"""
    global _orchestrator_instance
    if _orchestrator_instance is None:
        _orchestrator_instance = AgenticOrchestrator(config)
    return _orchestrator_instance