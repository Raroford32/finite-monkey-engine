"""
Brilliant Memory System with Advanced Vector Embeddings

This module implements a sophisticated memory system that enables the agentic
system to learn from past discoveries, recognize patterns, and generate truly
novel exploits through associative reasoning.
"""

import asyncio
import json
import logging
import hashlib
import numpy as np
from typing import Any, Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
import pickle
import os
import faiss
from sentence_transformers import SentenceTransformer
import torch

from .llm_client import get_llm_client, LLMMessage

logger = logging.getLogger(__name__)


@dataclass
class MemoryNode:
    """Individual memory node with rich metadata"""
    id: str
    content: Dict[str, Any]
    embedding: np.ndarray
    timestamp: datetime
    access_count: int = 0
    importance: float = 0.5
    decay_rate: float = 0.01
    associations: Set[str] = field(default_factory=set)
    context: Dict[str, Any] = field(default_factory=dict)
    success_metrics: Dict[str, float] = field(default_factory=dict)


@dataclass
class MemoryCluster:
    """Cluster of related memories forming a concept"""
    id: str
    name: str
    centroid: np.ndarray
    members: Set[str] = field(default_factory=set)
    patterns: List[Dict[str, Any]] = field(default_factory=list)
    abstraction_level: int = 0
    
    def add_member(self, node_id: str, embedding: np.ndarray):
        """Add a new member and update centroid"""
        self.members.add(node_id)
        # Update centroid incrementally
        n = len(self.members)
        self.centroid = ((n - 1) * self.centroid + embedding) / n


class BrilliantMemory:
    """
    Advanced memory system with vector embeddings and associative reasoning
    
    Features:
    - Vector similarity search using FAISS
    - Hierarchical memory organization
    - Pattern abstraction and generalization
    - Temporal decay and importance weighting
    - Cross-modal associations
    """
    
    def __init__(self, embedding_dim: int = 768):
        """Initialize the brilliant memory system"""
        self.embedding_dim = embedding_dim
        
        # Memory storage
        self.nodes: Dict[str, MemoryNode] = {}
        self.clusters: Dict[str, MemoryCluster] = {}
        
        # Vector index for similarity search
        self.index = faiss.IndexFlatIP(embedding_dim)  # Inner product for similarity
        self.id_map: List[str] = []  # Maps FAISS index to node IDs
        
        # Embedding model
        self.encoder = SentenceTransformer('all-MiniLM-L6-v2')
        
        # LLM client for advanced reasoning
        self.llm_client = get_llm_client()
        
        # Pattern recognition
        self.discovered_patterns: List[Dict[str, Any]] = []
        self.pattern_templates: Dict[str, Any] = self._initialize_patterns()
        
        # Associative networks
        self.association_graph: Dict[str, Set[str]] = defaultdict(set)
        self.concept_hierarchy: Dict[str, List[str]] = defaultdict(list)
        
        # Learning parameters
        self.consolidation_threshold = 0.8
        self.abstraction_threshold = 5
        
        logger.info("Brilliant Memory System initialized")
    
    def _initialize_patterns(self) -> Dict[str, Any]:
        """Initialize pattern templates for recognition"""
        return {
            'exploit_chain': {
                'structure': ['vulnerability', 'trigger', 'payload', 'impact'],
                'variations': []
            },
            'vulnerability_combo': {
                'structure': ['vuln1', 'vuln2', 'interaction', 'amplification'],
                'variations': []
            },
            'novel_vector': {
                'structure': ['conventional', 'twist', 'unexpected_result'],
                'variations': []
            }
        }
    
    async def store(
        self,
        content: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
        importance: float = 0.5
    ) -> str:
        """Store a new memory with embeddings and associations"""
        # Generate ID
        memory_id = hashlib.sha256(
            json.dumps(content, sort_keys=True).encode()
        ).hexdigest()[:16]
        
        # Generate embedding
        text_representation = self._content_to_text(content)
        embedding = self.encoder.encode(text_representation)
        embedding = embedding / np.linalg.norm(embedding)  # Normalize
        
        # Create memory node
        node = MemoryNode(
            id=memory_id,
            content=content,
            embedding=embedding,
            timestamp=datetime.now(),
            importance=importance,
            context=context or {}
        )
        
        # Store node
        self.nodes[memory_id] = node
        
        # Add to vector index
        self.index.add(np.array([embedding]))
        self.id_map.append(memory_id)
        
        # Find associations
        await self._create_associations(node)
        
        # Check for pattern formation
        await self._detect_patterns(node)
        
        # Trigger consolidation if needed
        if len(self.nodes) % 100 == 0:
            await self._consolidate_memory()
        
        return memory_id
    
    async def recall(
        self,
        query: Dict[str, Any],
        k: int = 10,
        threshold: float = 0.7
    ) -> List[Tuple[MemoryNode, float]]:
        """Recall memories similar to query with associative expansion"""
        # Generate query embedding
        query_text = self._content_to_text(query)
        query_embedding = self.encoder.encode(query_text)
        query_embedding = query_embedding / np.linalg.norm(query_embedding)
        
        # Search in vector index
        distances, indices = self.index.search(np.array([query_embedding]), k * 2)
        
        # Collect results
        results = []
        for i, (dist, idx) in enumerate(zip(distances[0], indices[0])):
            if idx < len(self.id_map) and dist > threshold:
                node_id = self.id_map[idx]
                if node_id in self.nodes:
                    node = self.nodes[node_id]
                    
                    # Update access count and importance
                    node.access_count += 1
                    node.importance = self._update_importance(node)
                    
                    results.append((node, float(dist)))
        
        # Associative expansion - include associated memories
        expanded_results = await self._associative_recall(results, query)
        
        # Sort by combined score (similarity + importance)
        expanded_results.sort(
            key=lambda x: x[1] * x[0].importance,
            reverse=True
        )
        
        return expanded_results[:k]
    
    async def _create_associations(self, node: MemoryNode):
        """Create associations between memories using LLM reasoning"""
        # Find similar memories
        similar = await self.recall({'content': node.content}, k=5)
        
        for similar_node, similarity in similar:
            if similar_node.id != node.id and similarity > 0.8:
                # Create bidirectional association
                node.associations.add(similar_node.id)
                similar_node.associations.add(node.id)
                
                self.association_graph[node.id].add(similar_node.id)
                self.association_graph[similar_node.id].add(node.id)
        
        # Use LLM to find conceptual associations
        if len(similar) > 2:
            associations = await self._llm_find_associations(node, similar)
            for assoc_id in associations:
                if assoc_id in self.nodes:
                    node.associations.add(assoc_id)
                    self.association_graph[node.id].add(assoc_id)
    
    async def _llm_find_associations(
        self,
        node: MemoryNode,
        similar: List[Tuple[MemoryNode, float]]
    ) -> List[str]:
        """Use LLM to find non-obvious associations"""
        context = {
            'current': node.content,
            'similar': [n.content for n, _ in similar[:3]]
        }
        
        prompt = f"""Analyze these exploit discoveries and find non-obvious associations:

Current: {json.dumps(node.content, indent=2)}

Similar discoveries:
{json.dumps(context['similar'], indent=2)}

Identify conceptual connections that might not be immediately apparent.
Return IDs of memories that should be associated.

Format: JSON list of memory IDs
"""
        
        messages = [
            LLMMessage(role="system", content="You are a pattern recognition expert."),
            LLMMessage(role="user", content=prompt)
        ]
        
        response = await self.llm_client.complete(messages, temperature=0.3)
        
        try:
            associations = json.loads(response.content)
            return associations if isinstance(associations, list) else []
        except:
            return []
    
    async def _detect_patterns(self, node: MemoryNode):
        """Detect emerging patterns from stored memories"""
        # Get recent memories
        recent_nodes = sorted(
            self.nodes.values(),
            key=lambda n: n.timestamp,
            reverse=True
        )[:20]
        
        # Look for patterns
        for template_name, template in self.pattern_templates.items():
            matches = self._match_pattern(recent_nodes, template)
            
            if len(matches) >= 3:  # Pattern threshold
                pattern = {
                    'type': template_name,
                    'instances': matches,
                    'discovered_at': datetime.now().isoformat(),
                    'confidence': len(matches) / 20.0
                }
                
                self.discovered_patterns.append(pattern)
                
                # Create abstraction
                await self._create_abstraction(pattern)
    
    def _match_pattern(
        self,
        nodes: List[MemoryNode],
        template: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Match nodes against a pattern template"""
        matches = []
        
        # Simplified pattern matching - in production use more sophisticated methods
        structure = template['structure']
        
        for node in nodes:
            content = node.content
            if all(key in str(content) for key in structure):
                matches.append({
                    'node_id': node.id,
                    'match_score': 1.0
                })
        
        return matches
    
    async def _create_abstraction(self, pattern: Dict[str, Any]):
        """Create higher-level abstraction from pattern"""
        # Use LLM to create abstraction
        prompt = f"""Based on this discovered pattern, create a higher-level abstraction:

Pattern Type: {pattern['type']}
Instances: {len(pattern['instances'])}
Confidence: {pattern['confidence']}

Create a general principle or rule that explains this pattern.
This will help discover similar patterns in the future.

Format: JSON with 'principle', 'conditions', and 'applications'
"""
        
        messages = [
            LLMMessage(role="system", content="You are an expert at pattern abstraction."),
            LLMMessage(role="user", content=prompt)
        ]
        
        response = await self.llm_client.complete(messages, temperature=0.5)
        
        try:
            abstraction = json.loads(response.content)
            
            # Store abstraction as a special memory
            await self.store(
                {
                    'type': 'abstraction',
                    'pattern': pattern['type'],
                    'abstraction': abstraction
                },
                importance=0.9
            )
        except:
            pass
    
    async def _associative_recall(
        self,
        initial_results: List[Tuple[MemoryNode, float]],
        query: Dict[str, Any]
    ) -> List[Tuple[MemoryNode, float]]:
        """Expand recall through associations"""
        expanded = list(initial_results)
        seen_ids = {node.id for node, _ in initial_results}
        
        # Follow associations
        for node, score in initial_results[:5]:  # Top 5 for expansion
            for assoc_id in node.associations:
                if assoc_id not in seen_ids and assoc_id in self.nodes:
                    assoc_node = self.nodes[assoc_id]
                    # Reduced score for associations
                    expanded.append((assoc_node, score * 0.7))
                    seen_ids.add(assoc_id)
        
        return expanded
    
    def _update_importance(self, node: MemoryNode) -> float:
        """Update importance based on access patterns and success"""
        # Time decay
        age = (datetime.now() - node.timestamp).total_seconds() / 86400  # Days
        time_factor = np.exp(-node.decay_rate * age)
        
        # Access frequency
        access_factor = min(1.0, node.access_count / 10.0)
        
        # Success metrics
        success_factor = np.mean(list(node.success_metrics.values())) if node.success_metrics else 0.5
        
        # Association richness
        association_factor = min(1.0, len(node.associations) / 5.0)
        
        # Combined importance
        importance = (
            0.3 * time_factor +
            0.2 * access_factor +
            0.3 * success_factor +
            0.2 * association_factor
        )
        
        return importance
    
    async def _consolidate_memory(self):
        """Consolidate memories through clustering and abstraction"""
        logger.info("Starting memory consolidation...")
        
        # Remove low-importance memories
        to_remove = [
            node_id for node_id, node in self.nodes.items()
            if node.importance < 0.1
        ]
        
        for node_id in to_remove:
            del self.nodes[node_id]
        
        # Rebuild index
        self._rebuild_index()
        
        # Create clusters
        await self._create_clusters()
        
        logger.info(f"Consolidation complete. Active memories: {len(self.nodes)}")
    
    async def _create_clusters(self):
        """Create memory clusters for efficient retrieval"""
        if len(self.nodes) < 10:
            return
        
        # Get all embeddings
        embeddings = np.array([node.embedding for node in self.nodes.values()])
        
        # Simple k-means clustering
        n_clusters = min(10, len(self.nodes) // 5)
        kmeans = faiss.Kmeans(self.embedding_dim, n_clusters)
        kmeans.train(embeddings)
        
        # Assign nodes to clusters
        distances, labels = kmeans.index.search(embeddings, 1)
        
        for i, (node_id, node) in enumerate(self.nodes.items()):
            cluster_id = int(labels[i][0])
            
            if f"cluster_{cluster_id}" not in self.clusters:
                self.clusters[f"cluster_{cluster_id}"] = MemoryCluster(
                    id=f"cluster_{cluster_id}",
                    name=f"Cluster {cluster_id}",
                    centroid=kmeans.centroids[cluster_id]
                )
            
            self.clusters[f"cluster_{cluster_id}"].add_member(node_id, node.embedding)
    
    def _rebuild_index(self):
        """Rebuild FAISS index after consolidation"""
        self.index = faiss.IndexFlatIP(self.embedding_dim)
        self.id_map = []
        
        for node_id, node in self.nodes.items():
            self.index.add(np.array([node.embedding]))
            self.id_map.append(node_id)
    
    def _content_to_text(self, content: Dict[str, Any]) -> str:
        """Convert content dict to text for embedding"""
        # Extract key information
        parts = []
        
        if 'vulnerability_type' in content:
            parts.append(f"Vulnerability: {content['vulnerability_type']}")
        
        if 'description' in content:
            parts.append(content['description'])
        
        if 'attack_vector' in content:
            parts.append(f"Attack: {content['attack_vector']}")
        
        if 'impact' in content:
            parts.append(f"Impact: {content['impact']}")
        
        # Add all string values
        for key, value in content.items():
            if isinstance(value, str) and key not in ['id', 'timestamp']:
                parts.append(f"{key}: {value}")
        
        return " ".join(parts)
    
    async def generate_novel_combination(
        self,
        context: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Generate novel exploit by combining memories creatively"""
        # Get diverse memories
        diverse_memories = await self._get_diverse_memories(10)
        
        # Use LLM to combine creatively
        prompt = f"""You have access to these previous exploit discoveries:

{json.dumps([m.content for m in diverse_memories], indent=2)}

Current context:
{json.dumps(context, indent=2)}

Create a NOVEL exploit that combines elements from these discoveries in an unexpected way.
The exploit should be different from anything seen before.

Requirements:
1. Combine at least 3 different concepts
2. Create an unexpected interaction
3. Target a new attack surface
4. Be technically feasible

Format: JSON with 'exploit_type', 'components', 'attack_sequence', 'novelty_score'
"""
        
        messages = [
            LLMMessage(
                role="system",
                content="You are a creative security researcher finding novel attack vectors."
            ),
            LLMMessage(role="user", content=prompt)
        ]
        
        response = await self.llm_client.complete(messages, temperature=0.9)
        
        try:
            novel_exploit = json.loads(response.content)
            
            # Store this novel combination
            await self.store(
                novel_exploit,
                context={'generated': True, 'method': 'creative_combination'},
                importance=0.8
            )
            
            return novel_exploit
        except:
            return None
    
    async def _get_diverse_memories(self, k: int) -> List[MemoryNode]:
        """Get diverse memories for creative combination"""
        if len(self.nodes) < k:
            return list(self.nodes.values())
        
        # Use clustering to get diverse samples
        diverse = []
        
        # Get one from each cluster
        for cluster in list(self.clusters.values())[:k]:
            if cluster.members:
                member_id = list(cluster.members)[0]
                if member_id in self.nodes:
                    diverse.append(self.nodes[member_id])
        
        # Fill remaining with random high-importance memories
        remaining = k - len(diverse)
        high_importance = sorted(
            self.nodes.values(),
            key=lambda n: n.importance,
            reverse=True
        )
        
        for node in high_importance:
            if node not in diverse:
                diverse.append(node)
                if len(diverse) >= k:
                    break
        
        return diverse
    
    def save(self, path: str):
        """Save memory to disk"""
        data = {
            'nodes': self.nodes,
            'clusters': self.clusters,
            'patterns': self.discovered_patterns,
            'associations': dict(self.association_graph),
            'hierarchy': dict(self.concept_hierarchy)
        }
        
        with open(path, 'wb') as f:
            pickle.dump(data, f)
    
    def load(self, path: str):
        """Load memory from disk"""
        if os.path.exists(path):
            with open(path, 'rb') as f:
                data = pickle.load(f)
                
            self.nodes = data.get('nodes', {})
            self.clusters = data.get('clusters', {})
            self.discovered_patterns = data.get('patterns', [])
            self.association_graph = defaultdict(set, data.get('associations', {}))
            self.concept_hierarchy = defaultdict(list, data.get('hierarchy', {}))
            
            # Rebuild index
            self._rebuild_index()
            
            logger.info(f"Loaded {len(self.nodes)} memories from disk")