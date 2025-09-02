#!/usr/bin/env python3
"""
Test script for the Advanced Agentic Exploit Discovery System
"""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from main import ExploitDiscoverySystem


async def test_system():
    """Test the exploit discovery system"""
    print("="*60)
    print("AAEDS - System Test")
    print("="*60)
    
    # Initialize system
    print("\n[*] Initializing system...")
    system = ExploitDiscoverySystem()
    
    # Test on vulnerable contract
    test_contract = "test/vulnerable_contract.sol"
    
    print(f"\n[*] Analyzing test contract: {test_contract}")
    print("[*] This may take a few moments...\n")
    
    try:
        # Run analysis
        report = await system.analyze_target(
            test_contract,
            target_type='codebase',
            deep_analysis=True
        )
        
        # Display results
        print("\n" + "="*60)
        print("ANALYSIS COMPLETE")
        print("="*60)
        
        print(f"\n[+] Total Exploits Found: {report['total_exploits']}")
        
        if report['exploits_by_severity']:
            print("\n[+] Exploits by Severity:")
            for severity, count in report['exploits_by_severity'].items():
                print(f"    - {severity.upper()}: {count}")
        
        if report['exploits_by_type']:
            print("\n[+] Exploits by Type:")
            for vuln_type, count in report['exploits_by_type'].items():
                print(f"    - {vuln_type}: {count}")
        
        if report['exploits']:
            print("\n[+] Detailed Findings:")
            for i, exploit in enumerate(report['exploits'][:5], 1):  # Show first 5
                print(f"\n  {i}. {exploit['type'].upper()}")
                print(f"     Severity: {exploit['severity']}")
                print(f"     Confidence: {exploit['confidence']:.1%}")
                if exploit.get('target_function'):
                    print(f"     Function: {exploit['target_function']}")
        
        # Get system statistics
        stats = system.get_statistics()
        print("\n" + "="*60)
        print("SYSTEM STATISTICS")
        print("="*60)
        print(f"Total Exploits in Memory: {stats['total_exploits']}")
        print(f"Analyses Performed: {stats['analysis_count']}")
        
        print("\n[+] Test completed successfully!")
        
    except Exception as e:
        print(f"\n[!] Error during analysis: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == '__main__':
    print("\nAdvanced Agentic Exploit Discovery System")
    print("Test Suite v1.0\n")
    
    exit_code = asyncio.run(test_system())
    sys.exit(exit_code)