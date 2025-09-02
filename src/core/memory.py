"""
Memory System for Exploit Discovery

This module implements a memory system for storing and retrieving:
- Previously discovered exploits
- Analysis results and patterns
- Known vulnerabilities database
- Learning from past discoveries
"""

import asyncio
import json
import logging
import sqlite3
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
import hashlib
import pickle

logger = logging.getLogger(__name__)


@dataclass
class MemoryEntry:
    """Represents an entry in the memory system"""
    id: str
    type: str  # exploit, analysis, pattern, vulnerability
    data: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.now)
    tags: List[str] = field(default_factory=list)
    confidence: float = 1.0
    access_count: int = 0
    last_accessed: datetime = field(default_factory=datetime.now)


class MemorySystem:
    """
    Advanced memory system for exploit discovery
    
    Features:
    - Persistent storage of discoveries
    - Fast retrieval and search
    - Pattern learning and evolution
    - Knowledge graph construction
    """
    
    def __init__(self, db_path: Optional[str] = None):
        """Initialize the memory system"""
        self.db_path = db_path or "exploit_memory.db"
        self.conn = None
        self.cache = {}  # In-memory cache for fast access
        self.knowledge_graph = {}  # Relationships between entries
        
        self._initialize_database()
        self._load_cache()
        
        logger.info(f"Memory System initialized with database: {self.db_path}")
    
    def _initialize_database(self):
        """Initialize SQLite database for persistent storage"""
        self.conn = sqlite3.connect(self.db_path)
        cursor = self.conn.cursor()
        
        # Create tables
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS memory_entries (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                data BLOB NOT NULL,
                timestamp REAL NOT NULL,
                tags TEXT,
                confidence REAL DEFAULT 1.0,
                access_count INTEGER DEFAULT 0,
                last_accessed REAL
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS exploits (
                id TEXT PRIMARY KEY,
                vulnerability_type TEXT,
                severity TEXT,
                confidence REAL,
                target_contract TEXT,
                discovered_date REAL,
                validation_status TEXT,
                poc_code TEXT,
                metadata BLOB
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                cve_id TEXT,
                vulnerability_class TEXT,
                description TEXT,
                severity TEXT,
                affected_versions TEXT,
                patch_available INTEGER,
                discovered_date REAL,
                metadata BLOB
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS patterns (
                id TEXT PRIMARY KEY,
                pattern_name TEXT,
                vulnerability_class TEXT,
                pattern_data BLOB,
                confidence_weight REAL,
                occurrences INTEGER DEFAULT 0,
                false_positive_rate REAL DEFAULT 0.0,
                created_date REAL,
                last_updated REAL
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_results (
                id TEXT PRIMARY KEY,
                target TEXT,
                analysis_type TEXT,
                result_data BLOB,
                timestamp REAL,
                exploits_found INTEGER DEFAULT 0
            )
        """)
        
        # Create indexes for fast search
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_memory_type 
            ON memory_entries(type)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_exploits_type 
            ON exploits(vulnerability_type)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_vulnerabilities_class 
            ON vulnerabilities(vulnerability_class)
        """)
        
        self.conn.commit()
    
    def _load_cache(self):
        """Load frequently accessed data into memory cache"""
        cursor = self.conn.cursor()
        
        # Load recent entries
        cursor.execute("""
            SELECT id, type, data, confidence 
            FROM memory_entries 
            WHERE last_accessed > ? 
            ORDER BY access_count DESC 
            LIMIT 1000
        """, (datetime.now().timestamp() - 86400 * 7,))  # Last 7 days
        
        for row in cursor.fetchall():
            entry_id, entry_type, data_blob, confidence = row
            try:
                data = pickle.loads(data_blob)
                self.cache[entry_id] = {
                    'type': entry_type,
                    'data': data,
                    'confidence': confidence
                }
            except:
                pass
    
    async def store_exploits(self, exploits: List[Any]):
        """Store discovered exploits in memory"""
        logger.info(f"Storing {len(exploits)} exploits in memory")
        
        cursor = self.conn.cursor()
        
        for exploit in exploits:
            exploit_id = exploit.id
            
            # Store in exploits table
            cursor.execute("""
                INSERT OR REPLACE INTO exploits 
                (id, vulnerability_type, severity, confidence, target_contract,
                 discovered_date, validation_status, poc_code, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                exploit_id,
                exploit.vulnerability_type,
                exploit.severity,
                exploit.confidence,
                exploit.target_contract,
                exploit.discovery_timestamp.timestamp(),
                exploit.validation_status,
                exploit.proof_of_concept,
                pickle.dumps(exploit.metadata)
            ))
            
            # Store in general memory
            memory_entry = MemoryEntry(
                id=exploit_id,
                type='exploit',
                data=self._exploit_to_dict(exploit),
                tags=[exploit.vulnerability_type, exploit.severity],
                confidence=exploit.confidence
            )
            
            await self._store_memory_entry(memory_entry)
            
            # Update cache
            self.cache[exploit_id] = {
                'type': 'exploit',
                'data': memory_entry.data,
                'confidence': exploit.confidence
            }
        
        self.conn.commit()
        
        # Update knowledge graph
        await self._update_knowledge_graph(exploits)
    
    async def store_analysis(self, analysis_results: Dict[str, Any]):
        """Store analysis results in memory"""
        analysis_id = self._generate_id(str(analysis_results))
        
        cursor = self.conn.cursor()
        
        # Store in analysis_results table
        cursor.execute("""
            INSERT OR REPLACE INTO analysis_results
            (id, target, analysis_type, result_data, timestamp, exploits_found)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            analysis_id,
            analysis_results.get('target', 'unknown'),
            analysis_results.get('type', 'unknown'),
            pickle.dumps(analysis_results),
            datetime.now().timestamp(),
            len(analysis_results.get('exploits', []))
        ))
        
        # Store in general memory
        memory_entry = MemoryEntry(
            id=analysis_id,
            type='analysis',
            data=analysis_results,
            tags=self._extract_tags(analysis_results)
        )
        
        await self._store_memory_entry(memory_entry)
        
        self.conn.commit()
    
    async def check_known_vulnerabilities(
        self,
        analysis_results: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Check if analysis matches known vulnerabilities"""
        known_vulns = []
        
        cursor = self.conn.cursor()
        
        # Extract relevant features from analysis
        contracts = analysis_results.get('contracts', [])
        functions = analysis_results.get('functions', [])
        patterns = analysis_results.get('patterns', [])
        
        # Search for matching vulnerabilities
        cursor.execute("""
            SELECT id, vulnerability_class, description, severity, metadata
            FROM vulnerabilities
            WHERE patch_available = 0
        """)
        
        for row in cursor.fetchall():
            vuln_id, vuln_class, description, severity, metadata_blob = row
            
            try:
                metadata = pickle.loads(metadata_blob) if metadata_blob else {}
                
                # Check if vulnerability applies
                if self._vulnerability_matches(
                    vuln_class,
                    metadata,
                    analysis_results
                ):
                    known_vulns.append({
                        'id': vuln_id,
                        'class': vuln_class,
                        'description': description,
                        'severity': severity,
                        'metadata': metadata
                    })
            except:
                pass
        
        # Search in cached exploits
        for entry_id, entry_data in self.cache.items():
            if entry_data['type'] == 'exploit':
                exploit_data = entry_data['data']
                
                # Check similarity
                similarity = self._calculate_similarity(
                    exploit_data,
                    analysis_results
                )
                
                if similarity > 0.7:
                    known_vulns.append({
                        'id': entry_id,
                        'type': 'known_exploit',
                        'similarity': similarity,
                        'data': exploit_data
                    })
        
        logger.info(f"Found {len(known_vulns)} known vulnerabilities")
        
        return known_vulns
    
    async def search(
        self,
        query: Dict[str, Any],
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Search memory for relevant entries"""
        results = []
        
        cursor = self.conn.cursor()
        
        # Build SQL query based on search criteria
        conditions = []
        params = []
        
        if 'type' in query:
            conditions.append("type = ?")
            params.append(query['type'])
        
        if 'tags' in query:
            tag_conditions = []
            for tag in query['tags']:
                tag_conditions.append("tags LIKE ?")
                params.append(f"%{tag}%")
            conditions.append(f"({' OR '.join(tag_conditions)})")
        
        if 'min_confidence' in query:
            conditions.append("confidence >= ?")
            params.append(query['min_confidence'])
        
        where_clause = " AND ".join(conditions) if conditions else "1=1"
        
        # Execute search
        cursor.execute(f"""
            SELECT id, type, data, confidence, tags
            FROM memory_entries
            WHERE {where_clause}
            ORDER BY confidence DESC, access_count DESC
            LIMIT ?
        """, params + [limit])
        
        for row in cursor.fetchall():
            entry_id, entry_type, data_blob, confidence, tags_str = row
            
            try:
                data = pickle.loads(data_blob)
                results.append({
                    'id': entry_id,
                    'type': entry_type,
                    'data': data,
                    'confidence': confidence,
                    'tags': json.loads(tags_str) if tags_str else []
                })
                
                # Update access count
                self._update_access_count(entry_id)
                
            except:
                pass
        
        return results
    
    async def get_similar_exploits(
        self,
        exploit: Any,
        threshold: float = 0.6
    ) -> List[Dict[str, Any]]:
        """Find similar exploits in memory"""
        similar = []
        
        cursor = self.conn.cursor()
        
        # Search for exploits of same type
        cursor.execute("""
            SELECT id, vulnerability_type, severity, confidence, metadata
            FROM exploits
            WHERE vulnerability_type = ?
        """, (exploit.vulnerability_type,))
        
        for row in cursor.fetchall():
            exploit_id, vuln_type, severity, confidence, metadata_blob = row
            
            if exploit_id == exploit.id:
                continue
            
            try:
                metadata = pickle.loads(metadata_blob) if metadata_blob else {}
                
                # Calculate similarity
                similarity = self._calculate_exploit_similarity(
                    exploit,
                    {
                        'id': exploit_id,
                        'vulnerability_type': vuln_type,
                        'severity': severity,
                        'confidence': confidence,
                        'metadata': metadata
                    }
                )
                
                if similarity >= threshold:
                    similar.append({
                        'id': exploit_id,
                        'similarity': similarity,
                        'vulnerability_type': vuln_type,
                        'severity': severity
                    })
                    
            except:
                pass
        
        # Sort by similarity
        similar.sort(key=lambda x: x['similarity'], reverse=True)
        
        return similar
    
    async def learn_from_exploit(self, exploit: Any):
        """Learn from a discovered exploit to improve future detection"""
        logger.info(f"Learning from exploit {exploit.id}")
        
        # Extract patterns from exploit
        patterns = self._extract_patterns_from_exploit(exploit)
        
        cursor = self.conn.cursor()
        
        for pattern in patterns:
            pattern_id = self._generate_id(str(pattern))
            
            # Check if pattern exists
            cursor.execute("""
                SELECT occurrences, confidence_weight
                FROM patterns
                WHERE id = ?
            """, (pattern_id,))
            
            row = cursor.fetchone()
            
            if row:
                # Update existing pattern
                occurrences, confidence_weight = row
                new_occurrences = occurrences + 1
                new_confidence = min(1.0, confidence_weight * 1.05)
                
                cursor.execute("""
                    UPDATE patterns
                    SET occurrences = ?, confidence_weight = ?, last_updated = ?
                    WHERE id = ?
                """, (new_occurrences, new_confidence, datetime.now().timestamp(), pattern_id))
            else:
                # Store new pattern
                cursor.execute("""
                    INSERT INTO patterns
                    (id, pattern_name, vulnerability_class, pattern_data,
                     confidence_weight, occurrences, created_date, last_updated)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    pattern_id,
                    pattern.get('name', 'Unknown'),
                    exploit.vulnerability_type,
                    pickle.dumps(pattern),
                    0.6,  # Initial confidence for learned patterns
                    1,
                    datetime.now().timestamp(),
                    datetime.now().timestamp()
                ))
        
        self.conn.commit()
        
        # Update knowledge graph
        await self._add_to_knowledge_graph(exploit)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get memory system statistics"""
        cursor = self.conn.cursor()
        
        stats = {}
        
        # Count entries by type
        cursor.execute("""
            SELECT type, COUNT(*) 
            FROM memory_entries 
            GROUP BY type
        """)
        stats['entries_by_type'] = dict(cursor.fetchall())
        
        # Count exploits by severity
        cursor.execute("""
            SELECT severity, COUNT(*) 
            FROM exploits 
            GROUP BY severity
        """)
        stats['exploits_by_severity'] = dict(cursor.fetchall())
        
        # Count patterns
        cursor.execute("SELECT COUNT(*) FROM patterns")
        stats['total_patterns'] = cursor.fetchone()[0]
        
        # Count vulnerabilities
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        stats['known_vulnerabilities'] = cursor.fetchone()[0]
        
        # Cache statistics
        stats['cache_size'] = len(self.cache)
        stats['knowledge_graph_nodes'] = len(self.knowledge_graph)
        
        return stats
    
    # Helper methods
    
    async def _store_memory_entry(self, entry: MemoryEntry):
        """Store a memory entry in database"""
        cursor = self.conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO memory_entries
            (id, type, data, timestamp, tags, confidence, access_count, last_accessed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            entry.id,
            entry.type,
            pickle.dumps(entry.data),
            entry.timestamp.timestamp(),
            json.dumps(entry.tags),
            entry.confidence,
            entry.access_count,
            entry.last_accessed.timestamp()
        ))
    
    def _exploit_to_dict(self, exploit: Any) -> Dict[str, Any]:
        """Convert exploit object to dictionary"""
        return {
            'id': exploit.id,
            'vulnerability_type': exploit.vulnerability_type,
            'severity': exploit.severity,
            'confidence': exploit.confidence,
            'target_contract': exploit.target_contract,
            'target_function': exploit.target_function,
            'steps': exploit.steps,
            'poc': exploit.proof_of_concept
        }
    
    def _generate_id(self, content: str) -> str:
        """Generate unique ID from content"""
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _extract_tags(self, data: Dict[str, Any]) -> List[str]:
        """Extract tags from data"""
        tags = []
        
        # Add type tags
        if 'type' in data:
            tags.append(data['type'])
        
        # Add vulnerability tags
        if 'vulnerability_type' in data:
            tags.append(data['vulnerability_type'])
        
        # Add severity tags
        if 'severity' in data:
            tags.append(data['severity'])
        
        # Add contract tags
        if 'contracts' in data:
            tags.extend([c.get('name', '') for c in data['contracts']][:5])
        
        return tags
    
    def _vulnerability_matches(
        self,
        vuln_class: str,
        metadata: Dict[str, Any],
        analysis_results: Dict[str, Any]
    ) -> bool:
        """Check if vulnerability matches analysis results"""
        # Simple matching logic
        patterns = analysis_results.get('patterns', [])
        
        for pattern in patterns:
            if pattern.get('vulnerability_class') == vuln_class:
                return True
        
        return False
    
    def _calculate_similarity(
        self,
        data1: Dict[str, Any],
        data2: Dict[str, Any]
    ) -> float:
        """Calculate similarity between two data entries"""
        # Simple similarity based on common keys and values
        keys1 = set(data1.keys())
        keys2 = set(data2.keys())
        
        common_keys = keys1.intersection(keys2)
        
        if not common_keys:
            return 0.0
        
        matches = 0
        for key in common_keys:
            if data1[key] == data2[key]:
                matches += 1
        
        return matches / len(keys1.union(keys2))
    
    def _calculate_exploit_similarity(
        self,
        exploit1: Any,
        exploit2: Dict[str, Any]
    ) -> float:
        """Calculate similarity between two exploits"""
        score = 0.0
        
        # Same vulnerability type
        if exploit1.vulnerability_type == exploit2['vulnerability_type']:
            score += 0.4
        
        # Similar severity
        if exploit1.severity == exploit2['severity']:
            score += 0.2
        
        # Similar confidence
        conf_diff = abs(exploit1.confidence - exploit2['confidence'])
        score += 0.2 * (1 - conf_diff)
        
        # Similar metadata
        if exploit1.metadata and exploit2.get('metadata'):
            meta_sim = self._calculate_similarity(
                exploit1.metadata,
                exploit2['metadata']
            )
            score += 0.2 * meta_sim
        
        return score
    
    def _extract_patterns_from_exploit(self, exploit: Any) -> List[Dict[str, Any]]:
        """Extract patterns from an exploit"""
        patterns = []
        
        # Extract step patterns
        if exploit.steps:
            step_pattern = {
                'name': f"Step pattern for {exploit.vulnerability_type}",
                'steps': [s.get('action') for s in exploit.steps],
                'vulnerability_type': exploit.vulnerability_type
            }
            patterns.append(step_pattern)
        
        # Extract precondition patterns
        if exploit.preconditions:
            precond_pattern = {
                'name': f"Preconditions for {exploit.vulnerability_type}",
                'preconditions': exploit.preconditions,
                'vulnerability_type': exploit.vulnerability_type
            }
            patterns.append(precond_pattern)
        
        return patterns
    
    async def _update_knowledge_graph(self, exploits: List[Any]):
        """Update knowledge graph with new exploits"""
        for exploit in exploits:
            node_id = exploit.id
            
            # Add node
            self.knowledge_graph[node_id] = {
                'type': 'exploit',
                'data': self._exploit_to_dict(exploit),
                'connections': []
            }
            
            # Find connections to existing nodes
            similar = await self.get_similar_exploits(exploit)
            
            for sim in similar[:5]:  # Limit connections
                self.knowledge_graph[node_id]['connections'].append({
                    'target': sim['id'],
                    'weight': sim['similarity']
                })
    
    async def _add_to_knowledge_graph(self, exploit: Any):
        """Add single exploit to knowledge graph"""
        await self._update_knowledge_graph([exploit])
    
    def _update_access_count(self, entry_id: str):
        """Update access count for an entry"""
        cursor = self.conn.cursor()
        
        cursor.execute("""
            UPDATE memory_entries
            SET access_count = access_count + 1,
                last_accessed = ?
            WHERE id = ?
        """, (datetime.now().timestamp(), entry_id))
        
        self.conn.commit()
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            logger.info("Memory system database connection closed")