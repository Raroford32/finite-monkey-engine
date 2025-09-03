#!/usr/bin/env python3
"""
Demo: Fully Agentic Exploit Discovery System

This demonstrates the system operating in fully LLM-driven mode where:
- All decisions are made by specialized AI agents
- The system learns from discoveries and improves over time
- Novel exploits are discovered through creative reasoning
- Brilliant memory enables pattern recognition and innovation
"""

import asyncio
import sys
import os
from pathlib import Path
from dotenv import load_dotenv
import json

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

# Load environment variables
load_dotenv()

from core.agentic_orchestrator import get_agentic_orchestrator
from core.brilliant_memory import BrilliantMemory


async def demonstrate_agentic_discovery():
    """Demonstrate the fully agentic exploit discovery system"""
    print("=" * 80)
    print("🤖 AGENTIC EXPLOIT DISCOVERY SYSTEM DEMO 🤖")
    print("=" * 80)
    print("\nThis system uses multiple specialized AI agents to discover novel exploits")
    print("through collaborative reasoning and brilliant memory.\n")
    
    # Initialize the system
    config = {
        'memory_path': './data/demo_memory.pkl',
        'use_agentic': True
    }
    
    orchestrator = get_agentic_orchestrator(config)
    
    # Example 1: Discover exploits in a DeFi protocol
    print("\n📊 Example 1: DeFi Protocol Analysis")
    print("-" * 40)
    
    defi_context = {
        'protocol_type': 'AMM',
        'features': ['liquidity pools', 'flash loans', 'governance tokens'],
        'tvl': 1000000000,  # $1B TVL
        'description': """
        A decentralized exchange with:
        - Automated market maker pools
        - Flash loan functionality
        - Governance token with voting power
        - Yield farming rewards
        - Cross-chain bridge integration
        """
    }
    
    print(f"Analyzing DeFi protocol with ${defi_context['tvl']:,} TVL...")
    print("Agents working: Strategist, Researcher, Explorer, Creative, Adversary...\n")
    
    exploits = await orchestrator.discover_novel_exploits(
        target="DeFi_Protocol_V2",
        context=defi_context
    )
    
    print(f"\n✅ Discovered {len(exploits)} potential exploits:")
    for i, exploit in enumerate(exploits, 1):
        print(f"\n{i}. {exploit.get('vulnerability_type', 'Unknown')}")
        print(f"   Severity: {exploit.get('severity', 'N/A')}")
        print(f"   Confidence: {exploit.get('confidence', 0):.1%}")
        if 'attack_vector' in exploit:
            print(f"   Attack Vector: {exploit['attack_vector']}")
        if 'funds_at_risk' in exploit:
            print(f"   Potential Impact: ${exploit['funds_at_risk']:,.0f}")
    
    # Example 2: Cross-protocol attack discovery
    print("\n\n🔗 Example 2: Cross-Protocol Attack Discovery")
    print("-" * 40)
    
    cross_protocol_context = {
        'protocols': ['Lending_Protocol_A', 'DEX_B', 'Yield_Aggregator_C'],
        'interactions': [
            'A provides collateral for B',
            'B provides liquidity to C',
            'C deposits back to A'
        ],
        'description': """
        Three interconnected protocols where:
        - Users can use lending positions as collateral
        - DEX liquidity can be leveraged for yield
        - Circular dependencies exist between protocols
        """
    }
    
    print("Analyzing cross-protocol interactions...")
    print("Memory system recalling similar past discoveries...\n")
    
    cross_exploits = await orchestrator.discover_novel_exploits(
        target="Cross_Protocol_System",
        context=cross_protocol_context
    )
    
    print(f"\n✅ Discovered {len(cross_exploits)} cross-protocol exploits")
    
    # Example 3: Novel attack vector generation
    print("\n\n💡 Example 3: Novel Attack Vector Generation")
    print("-" * 40)
    
    print("Creative and Explorer agents generating unconventional approaches...")
    print("Memory system combining past patterns in new ways...\n")
    
    # The system will use its brilliant memory to combine past discoveries
    novel_context = {
        'request': 'Generate completely novel attack vectors',
        'constraints': ['Must be technically feasible', 'Never seen before'],
        'target_impact': 'High severity with minimal traces'
    }
    
    novel_exploits = await orchestrator.discover_novel_exploits(
        target="Novel_Target",
        context=novel_context
    )
    
    if novel_exploits:
        print("🚨 NOVEL EXPLOIT DISCOVERED:")
        novel = novel_exploits[0]
        print(f"Type: {novel.get('vulnerability_type', 'Unknown')}")
        if 'novelty_score' in novel:
            print(f"Novelty Score: {novel['novelty_score']}/10")
        if 'components' in novel:
            print(f"Combines: {', '.join(novel['components'])}")
    
    # Show memory insights
    print("\n\n🧠 Brilliant Memory Insights")
    print("-" * 40)
    
    memory = orchestrator.global_memory
    insights = memory.get_insights({})
    
    print(f"Total discoveries stored: {len(memory.long_term)}")
    print(f"Patterns identified: {len(insights['patterns'])}")
    print(f"Successful strategies: {len(insights['successful_strategies'])}")
    
    if insights['patterns']:
        print("\nTop patterns:")
        for pattern in insights['patterns'][:3]:
            print(f"- {pattern['type']}: {pattern['frequency']} instances "
                  f"(avg confidence: {pattern['avg_confidence']:.1%})")
    
    # Demonstrate autonomous learning
    print("\n\n📈 Autonomous Learning Demonstration")
    print("-" * 40)
    print("System learning from discoveries to improve future performance...")
    
    # Show how the system adapts
    print("\nAgent adaptation based on success rates:")
    for role, agent in list(orchestrator.agents.items())[:3]:
        print(f"- {role.value}: Temperature adjusted to {agent.temperature:.2f}")
    
    print("\n" + "=" * 80)
    print("✨ Demo Complete! The system continuously learns and improves. ✨")
    print("=" * 80)


async def demonstrate_memory_capabilities():
    """Demonstrate the brilliant memory system"""
    print("\n\n🧠 BRILLIANT MEMORY SYSTEM DEMO")
    print("=" * 80)
    
    memory = BrilliantMemory()
    
    # Store some discoveries
    discoveries = [
        {
            'vulnerability_type': 'reentrancy',
            'target': 'withdraw_function',
            'impact': 'drain_funds',
            'confidence': 0.9
        },
        {
            'vulnerability_type': 'price_manipulation',
            'target': 'oracle_feed',
            'impact': 'profit_extraction',
            'confidence': 0.85
        },
        {
            'vulnerability_type': 'flash_loan_attack',
            'target': 'liquidity_pool',
            'impact': 'arbitrage_profit',
            'confidence': 0.95
        }
    ]
    
    print("Storing discoveries in memory...")
    for discovery in discoveries:
        await memory.store(discovery, importance=discovery['confidence'])
    
    # Demonstrate recall
    print("\n📍 Semantic recall demonstration:")
    query = {'vulnerability_type': 'financial_attack', 'target': 'defi'}
    
    similar = await memory.recall(query, k=3)
    print(f"\nQuery: {query}")
    print(f"Found {len(similar)} similar memories:")
    
    for node, score in similar:
        print(f"- {node.content['vulnerability_type']}: "
              f"similarity={score:.2f}, importance={node.importance:.2f}")
    
    # Generate novel combination
    print("\n🔄 Novel exploit generation from memory:")
    novel = await memory.generate_novel_combination({'protocol': 'new_defi'})
    
    if novel:
        print(f"Generated novel exploit combining {len(novel.get('components', []))} concepts")
        print(f"Type: {novel.get('exploit_type', 'Unknown')}")


async def main():
    """Main demo entry point"""
    # Check if API key is configured
    if not os.getenv('OPENROUTER_API_KEY') or \
       os.getenv('OPENROUTER_API_KEY') == 'your_openrouter_api_key_here':
        print("❌ Error: OPENROUTER_API_KEY not configured!")
        print("Please set up your OpenRouter API key in .env file")
        return
    
    try:
        # Run main demo
        await demonstrate_agentic_discovery()
        
        # Optionally show memory capabilities
        # await demonstrate_memory_capabilities()
        
    except Exception as e:
        print(f"\n❌ Error during demo: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    print("\n🚀 Starting Agentic Exploit Discovery Demo...\n")
    asyncio.run(main())