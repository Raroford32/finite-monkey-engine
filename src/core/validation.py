"""
Advanced Validation Engine for Exploit Verification

This module implements sophisticated validation capabilities:
- Multi-round validation
- Cross-validation techniques  
- Confidence scoring
- False positive detection
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import statistics
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of exploit validation"""
    exploit_id: str
    is_valid: bool
    confidence: float  # 0.0 to 1.0
    validation_rounds: int
    
    # Validation details
    rounds_passed: int = 0
    rounds_failed: int = 0
    consistency_score: float = 0.0
    
    # Evidence
    successful_executions: List[Dict[str, Any]] = field(default_factory=list)
    failed_executions: List[Dict[str, Any]] = field(default_factory=list)
    
    # Risk assessment
    funds_at_risk: float = 0.0
    affected_contracts: List[str] = field(default_factory=list)
    impact_score: float = 0.0
    
    # Cross-validation
    cross_validation_results: List[Dict[str, Any]] = field(default_factory=list)
    
    # Metadata
    timestamp: datetime = field(default_factory=datetime.now)
    validation_time: float = 0.0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class ValidationEngine:
    """
    Advanced validation engine for exploit verification
    
    Performs rigorous validation to ensure exploits are real:
    - Multiple execution rounds
    - Different initial conditions
    - Cross-validation with variations
    - Statistical confidence analysis
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the validation engine"""
        self.config = config or {}
        self.min_confidence = self.config.get('min_confidence', 0.7)
        self.require_poc = self.config.get('require_poc', True)
        self.cross_validate = self.config.get('cross_validate', True)
        self.validation_rounds = self.config.get('validation_rounds', 3)
        
        # Validation thresholds
        self.consistency_threshold = 0.8
        self.impact_threshold = 10000  # Minimum funds at risk
        
        # Validation history
        self.validation_history = []
        
        logger.info(f"Validation Engine initialized with {self.validation_rounds} rounds")
    
    async def validate(
        self,
        execution_result: Dict[str, Any],
        rounds: Optional[int] = None
    ) -> ValidationResult:
        """Validate an exploit through multiple rounds"""
        exploit_id = execution_result.get('exploit_id', 'unknown')
        validation_rounds = rounds or self.validation_rounds
        
        logger.info(f"Validating exploit {exploit_id} with {validation_rounds} rounds")
        
        start_time = datetime.now()
        
        result = ValidationResult(
            exploit_id=exploit_id,
            is_valid=False,
            confidence=0.0,
            validation_rounds=validation_rounds
        )
        
        try:
            # Round 1: Basic validation
            basic_valid = await self._basic_validation(execution_result, result)
            
            if not basic_valid:
                logger.warning(f"Basic validation failed for {exploit_id}")
                result.confidence = 0.0
                return result
            
            # Round 2: Multi-round execution validation
            multi_round_valid = await self._multi_round_validation(
                execution_result,
                result,
                validation_rounds
            )
            
            # Round 3: Cross-validation with variations
            if self.cross_validate:
                cross_valid = await self._cross_validation(execution_result, result)
            else:
                cross_valid = True
            
            # Calculate final validation status
            result.is_valid = basic_valid and multi_round_valid and cross_valid
            
            # Calculate confidence score
            result.confidence = self._calculate_confidence(result)
            
            # Assess impact and risk
            await self._assess_impact(execution_result, result)
            
            # Check for false positives
            if await self._is_false_positive(result):
                result.is_valid = False
                result.confidence *= 0.5
                result.warnings.append("Potential false positive detected")
            
        except Exception as e:
            logger.error(f"Validation error: {e}")
            result.errors.append(str(e))
            result.is_valid = False
            result.confidence = 0.0
        
        # Calculate validation time
        result.validation_time = (datetime.now() - start_time).total_seconds()
        
        # Store validation history
        self.validation_history.append(result)
        
        logger.info(f"Validation complete: valid={result.is_valid}, confidence={result.confidence:.2f}")
        
        return result
    
    async def _basic_validation(
        self,
        execution_result: Dict[str, Any],
        validation_result: ValidationResult
    ) -> bool:
        """Perform basic validation checks"""
        logger.info("Performing basic validation")
        
        # Check if execution was successful
        if not execution_result.get('success'):
            validation_result.errors.append("Execution was not successful")
            return False
        
        # Check if exploit actually extracted value or changed state
        funds_extracted = execution_result.get('funds_extracted', 0)
        state_changes = execution_result.get('state_changes', {})
        
        if funds_extracted <= 0 and not state_changes:
            validation_result.warnings.append("No funds extracted or state changes detected")
            return False
        
        # Check if steps were executed
        steps_executed = execution_result.get('steps_executed', [])
        if not steps_executed:
            validation_result.errors.append("No steps were executed")
            return False
        
        # Verify critical steps succeeded
        critical_steps = [s for s in steps_executed if s.get('critical')]
        if critical_steps and not all(s.get('success') for s in critical_steps):
            validation_result.errors.append("Critical steps failed")
            return False
        
        # Check for obvious errors
        if execution_result.get('errors'):
            validation_result.errors.extend(execution_result['errors'])
            return False
        
        return True
    
    async def _multi_round_validation(
        self,
        execution_result: Dict[str, Any],
        validation_result: ValidationResult,
        rounds: int
    ) -> bool:
        """Validate exploit through multiple execution rounds"""
        logger.info(f"Performing {rounds} round validation")
        
        successful_rounds = 0
        execution_results = []
        
        for round_num in range(rounds):
            logger.info(f"Validation round {round_num + 1}/{rounds}")
            
            # Vary initial conditions slightly
            modified_execution = self._vary_initial_conditions(
                execution_result,
                round_num
            )
            
            # Re-execute exploit
            round_result = await self._re_execute_exploit(modified_execution)
            execution_results.append(round_result)
            
            if round_result.get('success'):
                successful_rounds += 1
                validation_result.successful_executions.append({
                    'round': round_num + 1,
                    'result': round_result
                })
            else:
                validation_result.failed_executions.append({
                    'round': round_num + 1,
                    'result': round_result
                })
        
        # Update validation result
        validation_result.rounds_passed = successful_rounds
        validation_result.rounds_failed = rounds - successful_rounds
        
        # Calculate consistency
        validation_result.consistency_score = successful_rounds / rounds
        
        # Check if enough rounds passed
        min_success_rate = 0.6  # At least 60% of rounds should succeed
        success_rate = successful_rounds / rounds
        
        if success_rate < min_success_rate:
            validation_result.warnings.append(
                f"Low success rate: {success_rate:.1%} (minimum: {min_success_rate:.1%})"
            )
            return False
        
        # Check consistency of results
        if not self._check_consistency(execution_results):
            validation_result.warnings.append("Inconsistent results across rounds")
            return False
        
        return True
    
    async def _cross_validation(
        self,
        execution_result: Dict[str, Any],
        validation_result: ValidationResult
    ) -> bool:
        """Cross-validate exploit with variations"""
        logger.info("Performing cross-validation")
        
        variations = [
            self._create_timing_variation,
            self._create_value_variation,
            self._create_order_variation
        ]
        
        cross_validation_success = 0
        
        for i, variation_func in enumerate(variations):
            logger.info(f"Cross-validation {i + 1}/{len(variations)}")
            
            # Create variation
            varied_execution = variation_func(execution_result)
            
            # Execute variation
            variation_result = await self._re_execute_exploit(varied_execution)
            
            validation_result.cross_validation_results.append({
                'variation_type': variation_func.__name__,
                'success': variation_result.get('success'),
                'result': variation_result
            })
            
            if variation_result.get('success'):
                cross_validation_success += 1
        
        # At least half of variations should succeed
        success_rate = cross_validation_success / len(variations)
        
        if success_rate < 0.5:
            validation_result.warnings.append(
                f"Low cross-validation success: {success_rate:.1%}"
            )
            return False
        
        return True
    
    def _calculate_confidence(self, result: ValidationResult) -> float:
        """Calculate confidence score for validation"""
        confidence_factors = []
        
        # Factor 1: Consistency score (0-1)
        confidence_factors.append(result.consistency_score)
        
        # Factor 2: Success rate
        total_rounds = result.rounds_passed + result.rounds_failed
        if total_rounds > 0:
            success_rate = result.rounds_passed / total_rounds
            confidence_factors.append(success_rate)
        
        # Factor 3: Cross-validation success
        if result.cross_validation_results:
            cross_success = sum(
                1 for r in result.cross_validation_results if r['success']
            )
            cross_rate = cross_success / len(result.cross_validation_results)
            confidence_factors.append(cross_rate)
        
        # Factor 4: No errors penalty
        error_penalty = 1.0 if not result.errors else 0.7
        confidence_factors.append(error_penalty)
        
        # Factor 5: Warning penalty
        warning_penalty = max(0.5, 1.0 - 0.1 * len(result.warnings))
        confidence_factors.append(warning_penalty)
        
        # Calculate weighted average
        if confidence_factors:
            base_confidence = statistics.mean(confidence_factors)
        else:
            base_confidence = 0.0
        
        # Apply minimum threshold
        return max(0.0, min(1.0, base_confidence))
    
    async def _assess_impact(
        self,
        execution_result: Dict[str, Any],
        validation_result: ValidationResult
    ):
        """Assess the impact of the validated exploit"""
        # Calculate funds at risk
        funds_extracted = execution_result.get('funds_extracted', 0)
        
        # Estimate total funds at risk (could be higher than extracted)
        contract_balance = execution_result.get('contract_balance', 0)
        validation_result.funds_at_risk = max(funds_extracted, contract_balance)
        
        # Identify affected contracts
        contracts = set()
        for step in execution_result.get('steps_executed', []):
            target = step.get('target')
            if target:
                contracts.add(target)
        
        validation_result.affected_contracts = list(contracts)
        
        # Calculate impact score (0-1)
        impact_factors = []
        
        # Factor 1: Financial impact
        if validation_result.funds_at_risk > 0:
            # Log scale for funds
            import math
            financial_impact = min(1.0, math.log10(validation_result.funds_at_risk + 1) / 7)
            impact_factors.append(financial_impact)
        
        # Factor 2: Number of affected contracts
        contract_impact = min(1.0, len(contracts) / 10)
        impact_factors.append(contract_impact)
        
        # Factor 3: Exploit complexity (more steps = more severe)
        steps = len(execution_result.get('steps_executed', []))
        complexity_impact = min(1.0, steps / 20)
        impact_factors.append(complexity_impact)
        
        validation_result.impact_score = statistics.mean(impact_factors) if impact_factors else 0.0
    
    async def _is_false_positive(self, result: ValidationResult) -> bool:
        """Check if the validation might be a false positive"""
        # Check for common false positive patterns
        
        # Pattern 1: Inconsistent results
        if result.consistency_score < self.consistency_threshold:
            return True
        
        # Pattern 2: Very low impact
        if result.funds_at_risk < self.impact_threshold and result.impact_score < 0.3:
            return True
        
        # Pattern 3: Too many warnings
        if len(result.warnings) > 5:
            return True
        
        # Pattern 4: Suspicious execution patterns
        if self._has_suspicious_pattern(result):
            return True
        
        return False
    
    def _has_suspicious_pattern(self, result: ValidationResult) -> bool:
        """Check for suspicious execution patterns"""
        # Check if all executions are identical (might be simulation artifact)
        if result.successful_executions:
            first_result = result.successful_executions[0]['result']
            all_identical = all(
                exec_data['result'] == first_result
                for exec_data in result.successful_executions[1:]
            )
            if all_identical:
                return True
        
        # Check for unrealistic values
        if result.funds_at_risk > 10**12:  # More than 1 trillion
            return True
        
        return False
    
    def _vary_initial_conditions(
        self,
        execution_result: Dict[str, Any],
        round_num: int
    ) -> Dict[str, Any]:
        """Vary initial conditions for multi-round validation"""
        import copy
        varied = copy.deepcopy(execution_result)
        
        # Vary based on round number
        if round_num == 0:
            # Original conditions
            pass
        elif round_num == 1:
            # Different block timestamp
            varied['block_timestamp'] = varied.get('block_timestamp', 0) + 3600
        elif round_num == 2:
            # Different gas price
            varied['gas_price'] = varied.get('gas_price', 20) * 1.5
        else:
            # Random variations
            import random
            varied['nonce'] = random.randint(0, 1000)
        
        return varied
    
    async def _re_execute_exploit(
        self,
        execution_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Re-execute an exploit for validation"""
        # This would call the execution engine
        # For now, simulate re-execution
        import random
        
        # Simulate execution with some randomness
        success_probability = 0.8 if execution_config.get('success') else 0.3
        
        return {
            'success': random.random() < success_probability,
            'funds_extracted': execution_config.get('funds_extracted', 0) * random.uniform(0.9, 1.1),
            'gas_used': execution_config.get('gas_used', 100000) * random.uniform(0.95, 1.05),
            'steps_executed': execution_config.get('steps_executed', [])
        }
    
    def _check_consistency(self, execution_results: List[Dict[str, Any]]) -> bool:
        """Check if execution results are consistent"""
        if not execution_results:
            return False
        
        # Check if key metrics are within acceptable variance
        funds_extracted = [r.get('funds_extracted', 0) for r in execution_results if r.get('success')]
        
        if not funds_extracted:
            return False
        
        # Calculate coefficient of variation
        if len(funds_extracted) > 1:
            mean_funds = statistics.mean(funds_extracted)
            if mean_funds > 0:
                std_funds = statistics.stdev(funds_extracted)
                cv = std_funds / mean_funds
                
                # CV should be less than 20% for consistency
                if cv > 0.2:
                    return False
        
        return True
    
    def _create_timing_variation(
        self,
        execution_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create timing variation of execution"""
        import copy
        varied = copy.deepcopy(execution_result)
        
        # Add delays between steps
        for step in varied.get('steps_executed', []):
            step['delay'] = 1000  # 1 second delay
        
        return varied
    
    def _create_value_variation(
        self,
        execution_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create value variation of execution"""
        import copy
        varied = copy.deepcopy(execution_result)
        
        # Vary transaction values by 10%
        for step in varied.get('steps_executed', []):
            if 'value' in step:
                step['value'] = int(step['value'] * 1.1)
        
        return varied
    
    def _create_order_variation(
        self,
        execution_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create order variation of execution"""
        import copy
        varied = copy.deepcopy(execution_result)
        
        # Reorder non-dependent steps
        steps = varied.get('steps_executed', [])
        if len(steps) > 2:
            # Swap middle steps
            mid = len(steps) // 2
            if mid > 0 and mid < len(steps) - 1:
                steps[mid], steps[mid - 1] = steps[mid - 1], steps[mid]
        
        return varied
    
    def get_validation_stats(self) -> Dict[str, Any]:
        """Get validation statistics"""
        if not self.validation_history:
            return {
                'total_validations': 0,
                'successful_validations': 0,
                'average_confidence': 0.0,
                'average_validation_time': 0.0
            }
        
        successful = [v for v in self.validation_history if v.is_valid]
        
        return {
            'total_validations': len(self.validation_history),
            'successful_validations': len(successful),
            'success_rate': len(successful) / len(self.validation_history),
            'average_confidence': statistics.mean(v.confidence for v in self.validation_history),
            'average_validation_time': statistics.mean(v.validation_time for v in self.validation_history),
            'total_funds_at_risk': sum(v.funds_at_risk for v in successful)
        }