#!/usr/bin/env python3
"""
Advanced Agentic Exploit Discovery System (AAEDS)

A cutting-edge, modular system for autonomous discovery of novel exploits
in protocols and codebases through advanced reasoning, planning, and validation.

Features:
- Multi-agent reasoning with symbolic execution
- Adaptive attack planning with backtracking
- Safe execution in forked environments
- Rigorous multi-round validation
- Pattern-based learning and memory
- Protocol and codebase analysis
"""

import asyncio
import argparse
import logging
import sys
from pathlib import Path
from typing import Optional, Dict, Any
import json

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from core import (
    ExploitDiscoveryEngine,
    ReasoningEngine,
    PlanningEngine,
    ExecutionEngine,
    ValidationEngine,
    ProtocolAnalyzer,
    CodebaseAnalyzer
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ExploitDiscoverySystem:
    """Main system orchestrator for exploit discovery"""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the exploit discovery system"""
        # Load configuration
        self.config = self._load_config(config_path) if config_path else self._default_config()
        
        # Initialize the main engine
        self.engine = ExploitDiscoveryEngine(self.config)
        
        logger.info("Exploit Discovery System initialized")
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from file"""
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            return self._default_config()
    
    def _default_config(self) -> Dict[str, Any]:
        """Return default configuration"""
        return {
            'reasoning': {
                'max_depth': 10,
                'enable_symbolic': True,
                'enable_fuzzing': True,
                'enable_invariant_detection': True,
                'enable_llm': True  # Enable LLM-enhanced reasoning
            },
            'planning': {
                'max_steps': 50,
                'enable_multi_path': True,
                'enable_backtracking': True,
                'strategy': 'adaptive'
            },
            'execution': {
                'mode': 'fork',
                'timeout': 300,
                'gas_limit': 30000000,
                'enable_state_diff': True,
                'enable_llm_poc': True  # Enable LLM-based PoC generation
            },
            'validation': {
                'min_confidence': 0.7,
                'require_poc': True,
                'cross_validate': True,
                'validation_rounds': 3
            }
        }
    
    async def analyze_target(
        self,
        target: str,
        target_type: str = 'auto',
        deep_analysis: bool = True
    ) -> Dict[str, Any]:
        """
        Analyze a target for exploits
        
        Args:
            target: Path to codebase, contract address, or protocol
            target_type: Type of target (auto, contract, protocol, codebase)
            deep_analysis: Whether to perform deep analysis
        
        Returns:
            Analysis results with discovered exploits
        """
        logger.info(f"Starting analysis of {target}")
        
        # Discover exploits
        exploits = await self.engine.discover_exploits(
            target,
            target_type=target_type,
            context={'deep_analysis': deep_analysis}
        )
        
        # Generate report
        report = self._generate_report(target, exploits)
        
        return report
    
    def _generate_report(self, target: str, exploits: list) -> Dict[str, Any]:
        """Generate analysis report"""
        report = {
            'target': target,
            'total_exploits': len(exploits),
            'exploits_by_severity': {},
            'exploits_by_type': {},
            'exploits': []
        }
        
        # Count by severity
        for severity in ['critical', 'high', 'medium', 'low']:
            count = len([e for e in exploits if e.severity == severity])
            if count > 0:
                report['exploits_by_severity'][severity] = count
        
        # Count by type
        type_counts = {}
        for exploit in exploits:
            vuln_type = exploit.vulnerability_type
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
        report['exploits_by_type'] = type_counts
        
        # Add exploit details
        for exploit in exploits:
            report['exploits'].append({
                'id': exploit.id,
                'type': exploit.vulnerability_type,
                'severity': exploit.severity,
                'confidence': exploit.confidence,
                'target_contract': exploit.target_contract,
                'target_function': exploit.target_function,
                'funds_at_risk': exploit.funds_at_risk,
                'poc_available': bool(exploit.proof_of_concept)
            })
        
        return report
    
    async def generate_poc(self, exploit_id: str) -> str:
        """Generate proof of concept for an exploit"""
        # Find exploit
        exploit = None
        for e in self.engine.discovered_exploits:
            if e.id == exploit_id:
                exploit = e
                break
        
        if not exploit:
            raise ValueError(f"Exploit {exploit_id} not found")
        
        # Generate PoC
        poc = await self.engine.execution_engine.generate_poc(exploit)
        
        return poc
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get system statistics"""
        return self.engine.get_statistics()


async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Advanced Agentic Exploit Discovery System'
    )
    
    parser.add_argument(
        'target',
        help='Target to analyze (contract address, protocol path, or codebase)'
    )
    
    parser.add_argument(
        '--type',
        choices=['auto', 'contract', 'protocol', 'codebase'],
        default='auto',
        help='Type of target'
    )
    
    parser.add_argument(
        '--config',
        help='Path to configuration file'
    )
    
    parser.add_argument(
        '--output',
        help='Output file for results (JSON)'
    )
    
    parser.add_argument(
        '--deep',
        action='store_true',
        help='Perform deep analysis'
    )
    
    parser.add_argument(
        '--generate-poc',
        action='store_true',
        help='Generate proof of concept code'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize system
    system = ExploitDiscoverySystem(args.config)
    
    try:
        # Analyze target
        logger.info(f"Analyzing {args.target}...")
        report = await system.analyze_target(
            args.target,
            target_type=args.type,
            deep_analysis=args.deep
        )
        
        # Display results
        print("\n" + "="*60)
        print("EXPLOIT DISCOVERY REPORT")
        print("="*60)
        print(f"Target: {report['target']}")
        print(f"Total Exploits Found: {report['total_exploits']}")
        
        if report['exploits_by_severity']:
            print("\nExploits by Severity:")
            for severity, count in report['exploits_by_severity'].items():
                print(f"  {severity.upper()}: {count}")
        
        if report['exploits_by_type']:
            print("\nExploits by Type:")
            for vuln_type, count in report['exploits_by_type'].items():
                print(f"  {vuln_type}: {count}")
        
        if report['exploits']:
            print("\nDetailed Findings:")
            for i, exploit in enumerate(report['exploits'], 1):
                print(f"\n{i}. Exploit ID: {exploit['id']}")
                print(f"   Type: {exploit['type']}")
                print(f"   Severity: {exploit['severity']}")
                print(f"   Confidence: {exploit['confidence']:.2%}")
                
                if exploit['target_contract']:
                    print(f"   Contract: {exploit['target_contract']}")
                if exploit['target_function']:
                    print(f"   Function: {exploit['target_function']}")
                if exploit['funds_at_risk']:
                    print(f"   Funds at Risk: ${exploit['funds_at_risk']:,.2f}")
                
                if args.generate_poc and exploit['poc_available']:
                    poc = await system.generate_poc(exploit['id'])
                    print(f"   PoC Generated: {len(poc)} bytes")
        
        # Save results if requested
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            print(f"\nResults saved to {args.output}")
        
        # Display statistics
        stats = system.get_statistics()
        print("\n" + "="*60)
        print("SYSTEM STATISTICS")
        print("="*60)
        print(f"Total Exploits Discovered: {stats['total_exploits']}")
        print(f"Total Analyses Performed: {stats['analysis_count']}")
        print(f"Total Funds at Risk: ${stats['total_funds_at_risk']:,.2f}")
        
    except KeyboardInterrupt:
        logger.info("Analysis interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    
    return 0


if __name__ == '__main__':
    # Run the async main function
    exit_code = asyncio.run(main())
    sys.exit(exit_code)