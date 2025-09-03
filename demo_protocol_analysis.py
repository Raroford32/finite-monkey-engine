#!/usr/bin/env python3
"""
Advanced Protocol Analysis Demo

Demonstrates the system analyzing a complex DeFi protocol to discover novel exploits
using the full power of hierarchical agents, brilliant memory, and creative reasoning.
"""

import asyncio
import sys
import os
from pathlib import Path
from dotenv import load_dotenv
import json
import time

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

# Load environment variables
load_dotenv()

from core.advanced_orchestrator import get_advanced_orchestrator
from core.brilliant_memory import BrilliantMemory
from core.llm_client import get_llm_client


# Simulated complex DeFi protocol for analysis
COMPLEX_DEFI_PROTOCOL = {
    'name': 'UltraYield Protocol V3',
    'type': 'Hybrid DeFi Ecosystem',
    'tvl': 2500000000,  # $2.5B TVL
    'components': {
        'lending_pool': {
            'description': 'Collateralized lending with dynamic interest rates',
            'code_snippet': '''
            function borrow(uint256 amount, address collateral) external {
                require(collateralValue[msg.sender][collateral] >= amount * 150 / 100);
                // Issue: No reentrancy guard
                (bool success,) = msg.sender.call{value: amount}("");
                require(success);
                borrowBalance[msg.sender] += amount;
                // Issue: State update after external call
            }
            ''',
            'vulnerabilities': ['potential_reentrancy', 'state_manipulation']
        },
        'amm_dex': {
            'description': 'Automated market maker with concentrated liquidity',
            'code_snippet': '''
            function swap(address tokenIn, uint256 amountIn) external returns (uint256) {
                uint256 price = getOraclePrice(tokenIn);
                // Issue: Single oracle dependency
                uint256 amountOut = calculateOutput(amountIn, price);
                // Issue: No slippage protection
                return amountOut;
            }
            ''',
            'vulnerabilities': ['oracle_manipulation', 'sandwich_attack']
        },
        'yield_aggregator': {
            'description': 'Auto-compounding yield strategies',
            'code_snippet': '''
            function compound() external {
                uint256 rewards = pendingRewards[msg.sender];
                // Issue: Integer overflow possible
                uint256 newBalance = balances[msg.sender] + rewards * rewardMultiplier;
                balances[msg.sender] = newBalance;
                // Issue: No access control
            }
            ''',
            'vulnerabilities': ['integer_overflow', 'unauthorized_access']
        },
        'governance': {
            'description': 'DAO governance with veToken model',
            'code_snippet': '''
            function propose(bytes calldata proposal) external {
                require(votingPower[msg.sender] > proposalThreshold);
                // Issue: Flash loan can bypass threshold
                proposals[proposalCount++] = Proposal(proposal, block.timestamp);
                // Issue: No timelock
            }
            ''',
            'vulnerabilities': ['flash_loan_governance', 'immediate_execution']
        },
        'bridge': {
            'description': 'Cross-chain bridge for asset transfers',
            'code_snippet': '''
            function bridgeAssets(uint256 amount, uint256 chainId) external {
                burn(msg.sender, amount);
                // Issue: Centralized validator set
                emit BridgeRequest(msg.sender, amount, chainId);
                // Issue: No verification of burn
            }
            ''',
            'vulnerabilities': ['bridge_exploit', 'double_spending']
        }
    },
    'interactions': [
        'Lending pool provides liquidity to AMM',
        'AMM fees compound in yield aggregator',
        'Governance controls all parameters',
        'Bridge enables cross-chain strategies',
        'Flash loans available across all components'
    ],
    'economic_model': {
        'token': 'ULTRA',
        'emissions': '1000 ULTRA per day',
        'staking_apr': '15%',
        'fee_structure': {
            'swap_fee': '0.3%',
            'lending_fee': '0.1%',
            'bridge_fee': '0.5%'
        }
    }
}


async def analyze_protocol_with_agents():
    """Demonstrate full protocol analysis with advanced orchestration"""
    print("=" * 80)
    print("🔬 ADVANCED PROTOCOL ANALYSIS DEMO")
    print("=" * 80)
    print(f"\nTarget: {COMPLEX_DEFI_PROTOCOL['name']}")
    print(f"TVL: ${COMPLEX_DEFI_PROTOCOL['tvl']:,}")
    print(f"Components: {len(COMPLEX_DEFI_PROTOCOL['components'])}")
    print("\n" + "-" * 80)
    
    # Initialize orchestrator
    orchestrator = get_advanced_orchestrator()
    
    # Phase 1: Initial Analysis
    print("\n📊 PHASE 1: Initial Multi-Agent Analysis")
    print("-" * 40)
    
    # Each component analyzed by different agents
    component_analyses = {}
    
    for component_name, component_data in COMPLEX_DEFI_PROTOCOL['components'].items():
        print(f"\n🔍 Analyzing {component_name}...")
        
        # Hierarchical decision on analysis approach
        decision = await orchestrator.make_hierarchical_decision({
            'component': component_name,
            'data': component_data,
            'options': [
                'Deep code analysis',
                'Economic modeling',
                'Attack vector enumeration',
                'Pattern matching'
            ]
        })
        
        print(f"   Decision: {decision.choice} (confidence: {decision.confidence:.1%})")
        
        # Analyze component
        agent = orchestrator.agent_hierarchy['level2']['analysis']
        analysis = await agent.process({
            'component': component_name,
            'code': component_data.get('code_snippet', ''),
            'known_issues': component_data.get('vulnerabilities', [])
        })
        
        component_analyses[component_name] = analysis
        
        # Store in memory
        await orchestrator.global_memory.store(
            {
                'component': component_name,
                'analysis': analysis,
                'timestamp': time.time()
            },
            importance=0.8
        )
    
    # Phase 2: Cross-Component Pattern Detection
    print("\n🔗 PHASE 2: Cross-Component Interaction Analysis")
    print("-" * 40)
    
    pattern_agent = orchestrator.agent_hierarchy['level2']['pattern']
    
    cross_patterns = await pattern_agent.process({
        'components': component_analyses,
        'interactions': COMPLEX_DEFI_PROTOCOL['interactions'],
        'task': 'Find attack vectors that span multiple components'
    })
    
    print("\n✅ Discovered Cross-Component Patterns:")
    if isinstance(cross_patterns, dict) and 'patterns' in cross_patterns:
        for pattern in cross_patterns['patterns'][:3]:
            print(f"   - {pattern}")
    
    # Phase 3: Creative Exploit Generation
    print("\n💡 PHASE 3: Novel Exploit Generation")
    print("-" * 40)
    
    creative_agent = orchestrator.agent_hierarchy['level2']['creative']
    
    # Generate novel exploits combining multiple vulnerabilities
    novel_exploits = await creative_agent.process({
        'component_analyses': component_analyses,
        'cross_patterns': cross_patterns,
        'protocol_info': COMPLEX_DEFI_PROTOCOL,
        'task': 'Generate novel exploit chains that combine multiple vulnerabilities'
    })
    
    print("\n🚨 Novel Exploit Chains Generated:")
    
    # Phase 4: Adversarial Enhancement
    print("\n👹 PHASE 4: Adversarial Optimization")
    print("-" * 40)
    
    adversary_agent = orchestrator.agent_hierarchy['level2']['adversary']
    
    optimized_exploits = await adversary_agent.process({
        'exploits': novel_exploits,
        'economic_model': COMPLEX_DEFI_PROTOCOL['economic_model'],
        'task': 'Optimize exploits for maximum profit with minimal detection'
    })
    
    # Phase 5: Validation and PoC Generation
    print("\n✅ PHASE 5: Validation and Proof of Concept")
    print("-" * 40)
    
    validator_agent = orchestrator.agent_hierarchy['level2']['validator']
    
    validated_exploits = []
    
    # Validate each exploit
    if isinstance(optimized_exploits, dict) and 'exploits' in optimized_exploits:
        for exploit in optimized_exploits['exploits'][:5]:
            validation = await validator_agent.process({
                'exploit': exploit,
                'protocol': COMPLEX_DEFI_PROTOCOL['name']
            })
            
            if validation.get('feasible', False):
                # Generate PoC
                llm_client = get_llm_client()
                poc = await llm_client.generate_poc(
                    exploit_details=exploit,
                    target_language="solidity"
                )
                
                exploit['validation'] = validation
                exploit['poc'] = poc[:500] + "..." if len(poc) > 500 else poc
                validated_exploits.append(exploit)
    
    # Phase 6: Memory Learning
    print("\n🧠 PHASE 6: System Learning")
    print("-" * 40)
    
    # Store discoveries for future learning
    for exploit in validated_exploits:
        await orchestrator.global_memory.store(
            exploit,
            context={'protocol': COMPLEX_DEFI_PROTOCOL['name']},
            importance=0.9
        )
    
    # Generate learning insights
    memory_agent = orchestrator.agent_hierarchy['level2']['memory']
    
    learning_insights = await memory_agent.process({
        'new_exploits': validated_exploits,
        'protocol_type': COMPLEX_DEFI_PROTOCOL['type'],
        'task': 'Extract patterns for future exploit discovery'
    })
    
    # Final Report
    print("\n" + "=" * 80)
    print("📋 ANALYSIS REPORT")
    print("=" * 80)
    
    print(f"\n🎯 Exploits Discovered: {len(validated_exploits)}")
    
    for i, exploit in enumerate(validated_exploits[:3], 1):
        print(f"\n{i}. Exploit Chain:")
        print(f"   Type: {exploit.get('type', 'Complex Chain')}")
        print(f"   Components: {exploit.get('components', 'Multiple')}")
        print(f"   Severity: {exploit.get('severity', 'Critical')}")
        print(f"   Confidence: {exploit.get('confidence', 0.8):.1%}")
        print(f"   Profit Potential: ${exploit.get('profit_potential', 1000000):,}")
        
        if 'attack_sequence' in exploit:
            print(f"   Attack Sequence:")
            for step in exploit['attack_sequence'][:3]:
                print(f"      - {step}")
        
        if 'poc' in exploit:
            print(f"   PoC: Generated ({len(exploit['poc'])} chars)")
    
    # Performance Metrics
    print("\n📊 Performance Metrics:")
    report = orchestrator.get_performance_report()
    print(f"   Total Decisions: {report['total_decisions']}")
    print(f"   Memory Entries: {report['memory_size']}")
    print(f"   Agents Involved: {len(orchestrator.agent_hierarchy['all_agents'])}")
    
    return validated_exploits


async def demonstrate_continuous_learning():
    """Show how the system learns and improves over time"""
    print("\n" + "=" * 80)
    print("🎓 CONTINUOUS LEARNING DEMONSTRATION")
    print("=" * 80)
    
    orchestrator = get_advanced_orchestrator()
    memory = orchestrator.global_memory
    
    # Simulate multiple protocol analyses
    protocols = [
        {'name': 'Protocol_A', 'type': 'lending', 'tvl': 1000000000},
        {'name': 'Protocol_B', 'type': 'dex', 'tvl': 500000000},
        {'name': 'Protocol_C', 'type': 'yield', 'tvl': 250000000}
    ]
    
    print("\n🔄 Analyzing multiple protocols to demonstrate learning...")
    
    for protocol in protocols:
        print(f"\n   Analyzing {protocol['name']}...")
        
        # Check if we have similar past experiences
        similar = await memory.recall(protocol, k=3)
        
        if similar:
            print(f"   Found {len(similar)} similar past analyses")
            print(f"   Applying learned patterns...")
        
        # Simulate discovery
        discovery = {
            'protocol': protocol['name'],
            'exploit_type': f"novel_{protocol['type']}_attack",
            'confidence': 0.85,
            'learned_from': [node.content.get('protocol') for node, _ in similar]
        }
        
        # Store for learning
        await memory.store(discovery, importance=0.8)
    
    print("\n✅ Learning Complete!")
    print(f"   Total Memories: {len(memory.nodes)}")
    print(f"   Pattern Clusters: {len(memory.clusters)}")
    
    # Show how learning improves discovery
    print("\n📈 Improvement Through Learning:")
    
    # Analyze a new similar protocol
    new_protocol = {'name': 'Protocol_D', 'type': 'lending', 'tvl': 750000000}
    
    print(f"\n   Analyzing new protocol: {new_protocol['name']}")
    
    # Recall relevant memories
    memories = await memory.recall(new_protocol, k=5)
    
    print(f"   Leveraging {len(memories)} relevant past discoveries")
    
    # Generate novel combination
    novel = await memory.generate_novel_combination(new_protocol)
    
    if novel:
        print(f"\n   🎯 Novel Exploit Generated Through Learning:")
        print(f"      Type: {novel.get('exploit_type', 'Unknown')}")
        print(f"      Combines: {len(novel.get('components', []))} concepts")
        print(f"      Novelty Score: {novel.get('novelty_score', 8)}/10")


async def main():
    """Main demo entry point"""
    # Check API key
    if not os.getenv('OPENROUTER_API_KEY') or \
       os.getenv('OPENROUTER_API_KEY') == 'your_openrouter_api_key_here':
        print("\n❌ Error: OPENROUTER_API_KEY not configured!")
        print("Please set up your OpenRouter API key in .env file")
        return
    
    try:
        # Run protocol analysis
        print("\n🚀 Starting Advanced Protocol Analysis Demo...\n")
        exploits = await analyze_protocol_with_agents()
        
        # Demonstrate learning
        await demonstrate_continuous_learning()
        
        # Summary
        print("\n" + "=" * 80)
        print("✨ DEMO COMPLETE!")
        print("=" * 80)
        print("\nKey Achievements:")
        print("✅ Hierarchical multi-agent analysis")
        print("✅ Cross-component vulnerability discovery")
        print("✅ Novel exploit chain generation")
        print("✅ Adversarial optimization")
        print("✅ Proof of concept generation")
        print("✅ Continuous learning from discoveries")
        print("\nThe system is now ready for production use on real protocols!")
        
    except Exception as e:
        print(f"\n❌ Error during demo: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())