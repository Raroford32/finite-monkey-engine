"""
Exploit Pattern Matching and Recognition System

This module implements pattern-based exploit detection:
- Known vulnerability patterns
- Machine learning-based pattern recognition
- Pattern evolution and learning
"""

import logging
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
import json
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class ExploitPattern:
    """Represents an exploit pattern"""
    id: str
    name: str
    vulnerability_class: str
    description: str
    
    # Pattern matching rules
    code_patterns: List[str] = field(default_factory=list)
    ast_patterns: List[Dict[str, Any]] = field(default_factory=dict)
    semantic_patterns: List[Dict[str, Any]] = field(default_factory=list)
    
    # Pattern metadata
    confidence_weight: float = 1.0
    false_positive_rate: float = 0.0
    discovered_date: datetime = field(default_factory=datetime.now)
    occurrences: int = 0
    
    # Learning data
    successful_matches: List[Dict[str, Any]] = field(default_factory=list)
    failed_matches: List[Dict[str, Any]] = field(default_factory=list)


class ExploitPatternMatcher:
    """
    Advanced pattern matching system for exploit discovery
    
    Features:
    - Multi-level pattern matching (code, AST, semantic)
    - Pattern learning and evolution
    - Confidence scoring
    - False positive reduction
    """
    
    def __init__(self):
        """Initialize the pattern matcher"""
        self.patterns = self._initialize_patterns()
        self.pattern_index = self._build_pattern_index()
        self.match_history = []
        
        logger.info(f"Pattern Matcher initialized with {len(self.patterns)} patterns")
    
    def _initialize_patterns(self) -> List[ExploitPattern]:
        """Initialize exploit pattern database"""
        patterns = []
        
        # Reentrancy patterns
        patterns.append(ExploitPattern(
            id="REENTRANCY_001",
            name="Classic Reentrancy",
            vulnerability_class="reentrancy",
            description="External call before state update",
            code_patterns=[
                r"\.call\{.*\}\(.*\).*\n.*state.*=",
                r"\.transfer\(.*\).*\n.*balance.*=",
                r"payable\(.*\)\..*\(.*\).*\n.*\w+\s*="
            ],
            semantic_patterns=[
                {"sequence": ["external_call", "state_update"]},
                {"missing": "reentrancy_guard"}
            ],
            confidence_weight=0.9
        ))
        
        patterns.append(ExploitPattern(
            id="REENTRANCY_002",
            name="Cross-Function Reentrancy",
            vulnerability_class="reentrancy",
            description="Reentrancy across multiple functions",
            code_patterns=[
                r"function\s+\w+.*external.*\{.*\.call",
                r"modifier\s+noReentrant"  # Check if missing
            ],
            semantic_patterns=[
                {"cross_function": True},
                {"shared_state": True}
            ],
            confidence_weight=0.85
        ))
        
        # Integer overflow/underflow patterns
        patterns.append(ExploitPattern(
            id="INTEGER_001",
            name="Unchecked Arithmetic",
            vulnerability_class="integer_overflow",
            description="Arithmetic operations without SafeMath",
            code_patterns=[
                r"[^SafeMath]\.\w*\s*\+\s*\w+",
                r"[^SafeMath]\.\w*\s*\*\s*\w+",
                r"uint\d*\s+\w+\s*=.*\+",
                r"uint\d*\s+\w+\s*=.*\*"
            ],
            semantic_patterns=[
                {"no_overflow_check": True},
                {"solidity_version": "<0.8.0"}
            ],
            confidence_weight=0.7
        ))
        
        # Access control patterns
        patterns.append(ExploitPattern(
            id="ACCESS_001",
            name="Missing Access Control",
            vulnerability_class="access_control",
            description="Critical function without access control",
            code_patterns=[
                r"function\s+(?:withdraw|transfer|mint|burn).*public",
                r"function\s+(?:set|update|change)(?:Owner|Admin).*public"
            ],
            semantic_patterns=[
                {"no_modifier": True},
                {"critical_operation": True}
            ],
            confidence_weight=0.8
        ))
        
        patterns.append(ExploitPattern(
            id="ACCESS_002",
            name="Incorrect Modifier Logic",
            vulnerability_class="access_control",
            description="Flawed access control modifier",
            code_patterns=[
                r"modifier\s+\w+.*\{.*msg\.sender\s*!=",
                r"require\(msg\.sender\s*!=.*owner"
            ],
            semantic_patterns=[
                {"inverted_logic": True}
            ],
            confidence_weight=0.9
        ))
        
        # Oracle manipulation patterns
        patterns.append(ExploitPattern(
            id="ORACLE_001",
            name="Spot Price Dependency",
            vulnerability_class="price_manipulation",
            description="Direct dependency on spot price",
            code_patterns=[
                r"getReserves\(\)",
                r"balanceOf\(address\(this\)\)",
                r"pair\.price\(\)"
            ],
            semantic_patterns=[
                {"no_twap": True},
                {"single_block_price": True}
            ],
            confidence_weight=0.85
        ))
        
        # Flash loan patterns
        patterns.append(ExploitPattern(
            id="FLASH_001",
            name="Flash Loan Vulnerability",
            vulnerability_class="flash_loan",
            description="Vulnerable to flash loan attacks",
            code_patterns=[
                r"flashLoan.*\{",
                r"function\s+\w*[Ff]lash\w*.*external"
            ],
            semantic_patterns=[
                {"price_dependency": True},
                {"same_block_execution": True}
            ],
            confidence_weight=0.8
        ))
        
        # Delegate call patterns
        patterns.append(ExploitPattern(
            id="DELEGATE_001",
            name="Unsafe Delegatecall",
            vulnerability_class="delegatecall",
            description="Delegatecall to untrusted contract",
            code_patterns=[
                r"delegatecall\(.*msg\.data",
                r"\.delegatecall\(abi\.encode"
            ],
            semantic_patterns=[
                {"user_controlled_target": True},
                {"storage_collision_risk": True}
            ],
            confidence_weight=0.95
        ))
        
        # Signature replay patterns
        patterns.append(ExploitPattern(
            id="SIGNATURE_001",
            name="Signature Replay",
            vulnerability_class="signature_replay",
            description="Missing nonce in signature verification",
            code_patterns=[
                r"ecrecover\(",
                r"function.*permit\("
            ],
            semantic_patterns=[
                {"no_nonce": True},
                {"no_deadline": True}
            ],
            confidence_weight=0.75
        ))
        
        # Front-running patterns
        patterns.append(ExploitPattern(
            id="FRONTRUN_001",
            name="Front-Running Vulnerability",
            vulnerability_class="front_running",
            description="Transaction order dependency",
            code_patterns=[
                r"function\s+\w*[Ss]wap.*public",
                r"function\s+\w*[Bb]uy.*public"
            ],
            semantic_patterns=[
                {"price_impact": True},
                {"no_slippage_protection": True}
            ],
            confidence_weight=0.7
        ))
        
        return patterns
    
    def _build_pattern_index(self) -> Dict[str, List[ExploitPattern]]:
        """Build index for efficient pattern lookup"""
        index = {}
        
        for pattern in self.patterns:
            # Index by vulnerability class
            if pattern.vulnerability_class not in index:
                index[pattern.vulnerability_class] = []
            index[pattern.vulnerability_class].append(pattern)
        
        return index
    
    def find_patterns(
        self,
        analysis_results: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Find matching patterns in analysis results"""
        logger.info("Searching for exploit patterns...")
        
        matches = []
        
        # Extract relevant data from analysis
        code = self._extract_code(analysis_results)
        ast_data = analysis_results.get('ast', {})
        semantic_data = self._extract_semantic_features(analysis_results)
        
        # Match against all patterns
        for pattern in self.patterns:
            match_result = self._match_pattern(
                pattern,
                code,
                ast_data,
                semantic_data
            )
            
            if match_result['matched']:
                matches.append({
                    'pattern_id': pattern.id,
                    'pattern_name': pattern.name,
                    'vulnerability_class': pattern.vulnerability_class,
                    'confidence': match_result['confidence'],
                    'evidence': match_result['evidence'],
                    'location': match_result.get('location')
                })
                
                # Update pattern statistics
                pattern.occurrences += 1
                pattern.successful_matches.append({
                    'timestamp': datetime.now().isoformat(),
                    'confidence': match_result['confidence']
                })
        
        # Store match history
        self.match_history.append({
            'timestamp': datetime.now().isoformat(),
            'matches_found': len(matches),
            'patterns_checked': len(self.patterns)
        })
        
        logger.info(f"Found {len(matches)} pattern matches")
        
        return matches
    
    def _extract_code(self, analysis_results: Dict[str, Any]) -> str:
        """Extract code from analysis results"""
        code_parts = []
        
        # Extract from functions
        for func in analysis_results.get('functions', []):
            if 'code' in func:
                code_parts.append(func['code'])
        
        # Extract from contracts
        for contract in analysis_results.get('contracts', []):
            if 'code' in contract:
                code_parts.append(contract['code'])
        
        # Extract from codebase analysis
        if 'codebase_analysis' in analysis_results:
            codebase = analysis_results['codebase_analysis']
            for func in codebase.get('functions', []):
                if 'code' in func:
                    code_parts.append(func['code'])
        
        return '\n'.join(code_parts)
    
    def _extract_semantic_features(
        self,
        analysis_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract semantic features from analysis"""
        features = {
            'has_reentrancy_guard': False,
            'uses_safe_math': False,
            'has_access_control': False,
            'has_twap': False,
            'has_nonce': False,
            'solidity_version': '0.8.0'
        }
        
        code = self._extract_code(analysis_results)
        
        # Check for reentrancy guard
        if 'nonReentrant' in code or 'ReentrancyGuard' in code:
            features['has_reentrancy_guard'] = True
        
        # Check for SafeMath
        if 'SafeMath' in code or 'using SafeMath' in code:
            features['uses_safe_math'] = True
        
        # Check for access control
        if 'onlyOwner' in code or 'require(msg.sender' in code:
            features['has_access_control'] = True
        
        # Check for TWAP
        if 'TWAP' in code or 'timeWeighted' in code:
            features['has_twap'] = True
        
        # Check for nonce
        if 'nonce' in code or '_nonces' in code:
            features['has_nonce'] = True
        
        # Extract Solidity version
        import re
        version_match = re.search(r'pragma solidity.*?(\d+\.\d+\.\d+)', code)
        if version_match:
            features['solidity_version'] = version_match.group(1)
        
        return features
    
    def _match_pattern(
        self,
        pattern: ExploitPattern,
        code: str,
        ast_data: Dict[str, Any],
        semantic_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Match a single pattern against data"""
        match_scores = []
        evidence = []
        location = None
        
        # Match code patterns
        if pattern.code_patterns:
            code_score, code_evidence, code_location = self._match_code_patterns(
                pattern.code_patterns,
                code
            )
            match_scores.append(code_score)
            evidence.extend(code_evidence)
            if code_location:
                location = code_location
        
        # Match AST patterns
        if pattern.ast_patterns:
            ast_score, ast_evidence = self._match_ast_patterns(
                pattern.ast_patterns,
                ast_data
            )
            match_scores.append(ast_score)
            evidence.extend(ast_evidence)
        
        # Match semantic patterns
        if pattern.semantic_patterns:
            semantic_score, semantic_evidence = self._match_semantic_patterns(
                pattern.semantic_patterns,
                semantic_data
            )
            match_scores.append(semantic_score)
            evidence.extend(semantic_evidence)
        
        # Calculate overall match confidence
        if match_scores:
            base_confidence = sum(match_scores) / len(match_scores)
            adjusted_confidence = base_confidence * pattern.confidence_weight
            
            # Reduce confidence based on false positive rate
            final_confidence = adjusted_confidence * (1 - pattern.false_positive_rate)
            
            matched = final_confidence > 0.5
        else:
            matched = False
            final_confidence = 0.0
        
        return {
            'matched': matched,
            'confidence': final_confidence,
            'evidence': evidence,
            'location': location
        }
    
    def _match_code_patterns(
        self,
        patterns: List[str],
        code: str
    ) -> Tuple[float, List[str], Optional[Dict[str, Any]]]:
        """Match code patterns using regex"""
        import re
        
        matches_found = 0
        evidence = []
        location = None
        
        for pattern_str in patterns:
            try:
                pattern = re.compile(pattern_str, re.MULTILINE | re.DOTALL)
                matches = pattern.finditer(code)
                
                for match in matches:
                    matches_found += 1
                    evidence.append(f"Code pattern matched: {pattern_str[:50]}...")
                    
                    if not location:
                        # Find line number
                        line_num = code[:match.start()].count('\n') + 1
                        location = {'line': line_num, 'match': match.group()[:100]}
                        
            except re.error:
                logger.warning(f"Invalid regex pattern: {pattern_str}")
        
        # Calculate score based on matches
        if patterns:
            score = min(1.0, matches_found / len(patterns))
        else:
            score = 0.0
        
        return score, evidence, location
    
    def _match_ast_patterns(
        self,
        patterns: List[Dict[str, Any]],
        ast_data: Dict[str, Any]
    ) -> Tuple[float, List[str]]:
        """Match AST patterns"""
        # Simplified AST matching
        matches = 0
        evidence = []
        
        for pattern in patterns:
            # Check if AST contains pattern
            if self._ast_contains_pattern(ast_data, pattern):
                matches += 1
                evidence.append(f"AST pattern matched: {pattern}")
        
        score = matches / len(patterns) if patterns else 0.0
        
        return score, evidence
    
    def _ast_contains_pattern(
        self,
        ast_data: Dict[str, Any],
        pattern: Dict[str, Any]
    ) -> bool:
        """Check if AST contains a pattern"""
        # Simplified check
        return False  # Would implement proper AST matching
    
    def _match_semantic_patterns(
        self,
        patterns: List[Dict[str, Any]],
        semantic_data: Dict[str, Any]
    ) -> Tuple[float, List[str]]:
        """Match semantic patterns"""
        matches = 0
        evidence = []
        
        for pattern in patterns:
            if self._semantic_matches(pattern, semantic_data):
                matches += 1
                evidence.append(f"Semantic pattern matched: {pattern}")
        
        score = matches / len(patterns) if patterns else 0.0
        
        return score, evidence
    
    def _semantic_matches(
        self,
        pattern: Dict[str, Any],
        semantic_data: Dict[str, Any]
    ) -> bool:
        """Check if semantic pattern matches"""
        # Check various semantic conditions
        
        if 'no_reentrancy_guard' in pattern:
            if not semantic_data.get('has_reentrancy_guard'):
                return True
        
        if 'no_overflow_check' in pattern:
            if not semantic_data.get('uses_safe_math'):
                return True
        
        if 'no_modifier' in pattern:
            if not semantic_data.get('has_access_control'):
                return True
        
        if 'no_twap' in pattern:
            if not semantic_data.get('has_twap'):
                return True
        
        if 'no_nonce' in pattern:
            if not semantic_data.get('has_nonce'):
                return True
        
        if 'solidity_version' in pattern:
            version = semantic_data.get('solidity_version', '0.8.0')
            if pattern['solidity_version'].startswith('<'):
                target_version = pattern['solidity_version'][1:]
                return version < target_version
        
        return False
    
    def update_patterns(
        self,
        exploits: List[Any]
    ):
        """Update patterns based on discovered exploits"""
        logger.info(f"Updating patterns with {len(exploits)} new exploits")
        
        for exploit in exploits:
            # Find matching pattern
            matching_pattern = self._find_matching_pattern(exploit)
            
            if matching_pattern:
                # Update pattern statistics
                matching_pattern.occurrences += 1
                
                # Adjust confidence weight based on success
                if exploit.validation_status == 'validated':
                    matching_pattern.confidence_weight = min(
                        1.0,
                        matching_pattern.confidence_weight * 1.05
                    )
                else:
                    matching_pattern.false_positive_rate = min(
                        1.0,
                        matching_pattern.false_positive_rate + 0.01
                    )
            else:
                # Create new pattern from exploit
                new_pattern = self._create_pattern_from_exploit(exploit)
                if new_pattern:
                    self.patterns.append(new_pattern)
                    self._rebuild_index()
    
    def _find_matching_pattern(self, exploit: Any) -> Optional[ExploitPattern]:
        """Find pattern matching an exploit"""
        vuln_class = exploit.vulnerability_type
        
        if vuln_class in self.pattern_index:
            for pattern in self.pattern_index[vuln_class]:
                # Simple matching by vulnerability class
                return pattern
        
        return None
    
    def _create_pattern_from_exploit(self, exploit: Any) -> Optional[ExploitPattern]:
        """Create new pattern from discovered exploit"""
        # Extract pattern features from exploit
        pattern_id = f"LEARNED_{hashlib.md5(str(exploit).encode()).hexdigest()[:8]}"
        
        return ExploitPattern(
            id=pattern_id,
            name=f"Learned: {exploit.vulnerability_type}",
            vulnerability_class=exploit.vulnerability_type,
            description=f"Pattern learned from exploit {exploit.id}",
            confidence_weight=0.6  # Start with lower confidence for learned patterns
        )
    
    def _rebuild_index(self):
        """Rebuild pattern index after updates"""
        self.pattern_index = self._build_pattern_index()
    
    def get_pattern_statistics(self) -> Dict[str, Any]:
        """Get statistics about patterns"""
        return {
            'total_patterns': len(self.patterns),
            'patterns_by_class': {
                vuln_class: len(patterns)
                for vuln_class, patterns in self.pattern_index.items()
            },
            'most_common_patterns': sorted(
                self.patterns,
                key=lambda p: p.occurrences,
                reverse=True
            )[:5],
            'average_confidence': sum(p.confidence_weight for p in self.patterns) / len(self.patterns) if self.patterns else 0,
            'total_matches': sum(p.occurrences for p in self.patterns)
        }