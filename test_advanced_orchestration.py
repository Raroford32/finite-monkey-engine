#!/usr/bin/env python3
"""
Comprehensive Testing Suite for Advanced Orchestration System

Tests:
- Hierarchical decision-making
- Large codebase analysis
- Novel exploit discovery
- Memory system performance
- Agent collaboration
- Parallel processing
"""

import asyncio
import sys
import os
import time
import json
from pathlib import Path
from typing import Dict, Any, List
from dotenv import load_dotenv

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

# Load environment variables
load_dotenv()

from core.advanced_orchestrator import (
    get_advanced_orchestrator,
    BaseAgent,
    AgentCapability,
    Decision
)
from core.brilliant_memory import BrilliantMemory


class TestResults:
    """Track test results"""
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.tests = []
    
    def add(self, name: str, passed: bool, details: str = ""):
        self.tests.append({
            'name': name,
            'passed': passed,
            'details': details
        })
        if passed:
            self.passed += 1
        else:
            self.failed += 1
    
    def print_summary(self):
        print("\n" + "=" * 80)
        print("TEST RESULTS SUMMARY")
        print("=" * 80)
        print(f"✅ Passed: {self.passed}")
        print(f"❌ Failed: {self.failed}")
        print(f"📊 Total: {self.passed + self.failed}")
        print(f"🎯 Success Rate: {(self.passed / (self.passed + self.failed) * 100):.1f}%")
        
        if self.failed > 0:
            print("\nFailed Tests:")
            for test in self.tests:
                if not test['passed']:
                    print(f"  - {test['name']}: {test['details']}")


async def test_hierarchical_decision_making():
    """Test hierarchical decision-making process"""
    print("\n🧪 Testing Hierarchical Decision Making...")
    print("-" * 40)
    
    orchestrator = get_advanced_orchestrator()
    
    # Test decision context
    decision_context = {
        'situation': 'Found potential reentrancy vulnerability',
        'options': [
            'Exploit immediately',
            'Analyze further',
            'Combine with other vulnerabilities',
            'Report and skip'
        ],
        'constraints': {
            'time_limit': 60,
            'risk_tolerance': 'medium'
        }
    }
    
    start_time = time.time()
    decision = await orchestrator.make_hierarchical_decision(decision_context)
    elapsed = time.time() - start_time
    
    print(f"✅ Decision made in {elapsed:.2f}s")
    print(f"   Choice: {decision.choice}")
    print(f"   Confidence: {decision.confidence:.1%}")
    print(f"   Agent: {decision.agent_id}")
    print(f"   Reasoning: {decision.reasoning[:100]}...")
    
    return decision.confidence > 0.5


async def test_large_codebase_analysis():
    """Test analysis of large codebase"""
    print("\n🧪 Testing Large Codebase Analysis...")
    print("-" * 40)
    
    orchestrator = get_advanced_orchestrator()
    
    # Simulate large codebase
    codebase_path = "/simulated/large/protocol"
    
    print(f"Analyzing codebase: {codebase_path}")
    print("Using parallel processing with multiple agents...")
    
    start_time = time.time()
    
    try:
        exploits = await orchestrator.analyze_large_codebase(
            codebase_path,
            chunk_size=500
        )
        elapsed = time.time() - start_time
        
        print(f"✅ Analysis complete in {elapsed:.2f}s")
        print(f"   Discovered {len(exploits)} potential exploits")
        
        if exploits:
            print("\n   Sample exploit:")
            exploit = exploits[0]
            print(f"   - Type: {exploit.get('type', 'Unknown')}")
            print(f"   - Severity: {exploit.get('severity', 'Unknown')}")
            print(f"   - Confidence: {exploit.get('confidence', 0):.1%}")
        
        return True
    except Exception as e:
        print(f"❌ Analysis failed: {e}")
        return False


async def test_memory_system():
    """Test brilliant memory system"""
    print("\n🧪 Testing Brilliant Memory System...")
    print("-" * 40)
    
    memory = BrilliantMemory(embedding_dim=768)
    
    # Store test discoveries
    test_discoveries = [
        {
            'id': 'test1',
            'type': 'reentrancy',
            'protocol': 'DeFi_A',
            'impact': 'high',
            'pattern': 'external_call_before_state_update'
        },
        {
            'id': 'test2',
            'type': 'price_manipulation',
            'protocol': 'DEX_B',
            'impact': 'critical',
            'pattern': 'oracle_dependency'
        },
        {
            'id': 'test3',
            'type': 'flash_loan',
            'protocol': 'Lending_C',
            'impact': 'high',
            'pattern': 'unchecked_loan_callback'
        }
    ]
    
    print("Storing discoveries...")
    for discovery in test_discoveries:
        await memory.store(discovery, importance=0.8)
    
    # Test recall
    print("\nTesting semantic recall...")
    query = {
        'seeking': 'DeFi vulnerability',
        'type': 'financial_attack'
    }
    
    similar = await memory.recall(query, k=2)
    print(f"✅ Found {len(similar)} similar memories")
    
    for node, score in similar:
        print(f"   - {node.content.get('type', 'Unknown')}: similarity={score:.2f}")
    
    # Test novel generation
    print("\nTesting novel exploit generation...")
    novel = await memory.generate_novel_combination({'target': 'new_protocol'})
    
    if novel:
        print(f"✅ Generated novel exploit:")
        print(f"   - Type: {novel.get('exploit_type', 'Unknown')}")
        print(f"   - Components: {len(novel.get('components', []))}")
        return True
    else:
        print("❌ Failed to generate novel exploit")
        return False


async def test_agent_collaboration():
    """Test multi-agent collaboration"""
    print("\n🧪 Testing Agent Collaboration...")
    print("-" * 40)
    
    orchestrator = get_advanced_orchestrator()
    
    # Get agents
    agents = orchestrator.agent_hierarchy['level2']
    
    # Test collaboration between creative and validator
    creative = agents.get('creative')
    validator = agents.get('validator')
    
    if not creative or not validator:
        print("❌ Required agents not found")
        return False
    
    # Creative generates idea
    print("Creative agent generating exploit idea...")
    creative_output = await creative.process({
        'task': 'Generate novel reentrancy exploit',
        'target': 'lending_protocol'
    })
    
    print(f"✅ Creative output generated")
    
    # Validator validates idea
    print("Validator agent checking feasibility...")
    validation = await validator.process({
        'exploit': creative_output,
        'check': 'technical_feasibility'
    })
    
    print(f"✅ Validation complete")
    print(f"   Feasible: {validation.get('feasible', False)}")
    print(f"   Confidence: {validation.get('confidence', 0):.1%}")
    
    return validation.get('feasible', False)


async def test_parallel_processing():
    """Test parallel processing capabilities"""
    print("\n🧪 Testing Parallel Processing...")
    print("-" * 40)
    
    orchestrator = get_advanced_orchestrator()
    
    # Create multiple analysis tasks
    tasks = [
        {'id': 'task1', 'type': 'analyze_contract', 'target': 'contract_a'},
        {'id': 'task2', 'type': 'find_patterns', 'target': 'protocol_b'},
        {'id': 'task3', 'type': 'generate_exploit', 'target': 'system_c'},
        {'id': 'task4', 'type': 'validate_finding', 'target': 'vuln_d'}
    ]
    
    print(f"Processing {len(tasks)} tasks in parallel...")
    
    start_time = time.time()
    
    # Process tasks in parallel
    async_tasks = []
    for task in tasks:
        agent = orchestrator.agent_hierarchy['all_agents'][
            hash(task['id']) % len(orchestrator.agent_hierarchy['all_agents'])
        ]
        async_tasks.append(agent.process(task))
    
    results = await asyncio.gather(*async_tasks, return_exceptions=True)
    
    elapsed = time.time() - start_time
    
    successful = sum(1 for r in results if not isinstance(r, Exception))
    
    print(f"✅ Processed {successful}/{len(tasks)} tasks in {elapsed:.2f}s")
    print(f"   Average time per task: {elapsed/len(tasks):.2f}s")
    
    return successful == len(tasks)


async def test_custom_agent_plugin():
    """Test custom agent plugin system"""
    print("\n🧪 Testing Custom Agent Plugin...")
    print("-" * 40)
    
    orchestrator = get_advanced_orchestrator()
    
    # Define custom agent
    class CustomExploitAgent(BaseAgent):
        def __init__(self, llm_client):
            super().__init__(
                agent_id="CustomExploit",
                capabilities=[AgentCapability.CREATIVITY, AgentCapability.ANALYSIS],
                llm_client=llm_client,
                temperature=0.8
            )
        
        async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
            return {
                'custom_analysis': 'Specialized exploit found',
                'confidence': 0.9,
                'details': input_data
            }
        
        async def decide(self, context: Dict[str, Any], options: List[Any]) -> Decision:
            return Decision(
                agent_id=self.agent_id,
                decision_type="custom",
                choice=options[0] if options else None,
                confidence=0.85,
                reasoning="Custom reasoning logic"
            )
    
    # Register custom agent
    orchestrator.register_custom_agent(CustomExploitAgent, "custom_exploit")
    print("✅ Custom agent registered")
    
    # Execute custom agent
    result = await orchestrator.execute_custom_agent(
        "custom_exploit",
        {'task': 'Find custom vulnerability'}
    )
    
    print(f"✅ Custom agent executed")
    print(f"   Result: {result.get('custom_analysis', 'None')}")
    print(f"   Confidence: {result.get('confidence', 0):.1%}")
    
    return result.get('confidence', 0) > 0.8


async def test_novel_exploit_synthesis():
    """Test novel exploit synthesis with proof generation"""
    print("\n🧪 Testing Novel Exploit Synthesis...")
    print("-" * 40)
    
    orchestrator = get_advanced_orchestrator()
    
    # Provide synthesis context
    synthesis_context = {
        'vulnerabilities_found': [
            {'type': 'reentrancy', 'location': 'withdraw_function'},
            {'type': 'integer_overflow', 'location': 'balance_calculation'},
            {'type': 'access_control', 'location': 'admin_functions'}
        ],
        'protocol_type': 'lending',
        'economic_model': 'collateralized_loans'
    }
    
    print("Generating novel exploit combinations...")
    
    # Generate novel exploits
    novel_exploits = await orchestrator._generate_novel_exploits(synthesis_context)
    
    print(f"✅ Generated {len(novel_exploits)} novel exploits")
    
    if novel_exploits:
        exploit = novel_exploits[0]
        print(f"\nNovel Exploit Details:")
        print(f"   Type: {exploit.get('type', 'Unknown')}")
        print(f"   Combines: {exploit.get('components', [])}")
        print(f"   Impact: {exploit.get('impact', 'Unknown')}")
        print(f"   Novelty: {exploit.get('novelty_score', 0)}/10")
        
        # Check for proof of concept
        if 'poc' in exploit:
            print(f"   PoC: Generated ({len(exploit['poc'])} bytes)")
        
        return True
    
    return False


async def test_performance_metrics():
    """Test performance tracking and metrics"""
    print("\n🧪 Testing Performance Metrics...")
    print("-" * 40)
    
    orchestrator = get_advanced_orchestrator()
    
    # Make several decisions to generate metrics
    for i in range(5):
        await orchestrator.make_hierarchical_decision({
            'test_decision': i,
            'options': ['option_a', 'option_b', 'option_c']
        })
    
    # Get performance report
    report = orchestrator.get_performance_report()
    
    print("✅ Performance Report:")
    print(f"   Total Decisions: {report['total_decisions']}")
    print(f"   Memory Size: {report['memory_size']}")
    print(f"   Working Memory: {report['working_memory_size']}")
    print(f"   Custom Agents: {report['custom_agents_registered']}")
    
    # Check agent metrics
    if report['agent_metrics']:
        print("\n   Agent Performance:")
        for agent_id, metrics in list(report['agent_metrics'].items())[:3]:
            print(f"   - {agent_id}:")
            print(f"     Decisions: {metrics.get('total_decisions', 0)}")
            print(f"     Avg Confidence: {metrics.get('avg_confidence', 0):.1%}")
    
    return report['total_decisions'] >= 5


async def run_all_tests():
    """Run all tests and report results"""
    print("=" * 80)
    print("🚀 ADVANCED ORCHESTRATION SYSTEM - COMPREHENSIVE TEST SUITE")
    print("=" * 80)
    
    # Check API key
    if not os.getenv('OPENROUTER_API_KEY') or \
       os.getenv('OPENROUTER_API_KEY') == 'your_openrouter_api_key_here':
        print("\n❌ Error: OPENROUTER_API_KEY not configured!")
        print("Please set up your OpenRouter API key in .env file")
        return
    
    results = TestResults()
    
    # Run tests
    tests = [
        ("Hierarchical Decision Making", test_hierarchical_decision_making),
        ("Large Codebase Analysis", test_large_codebase_analysis),
        ("Memory System", test_memory_system),
        ("Agent Collaboration", test_agent_collaboration),
        ("Parallel Processing", test_parallel_processing),
        ("Custom Agent Plugin", test_custom_agent_plugin),
        ("Novel Exploit Synthesis", test_novel_exploit_synthesis),
        ("Performance Metrics", test_performance_metrics)
    ]
    
    for test_name, test_func in tests:
        try:
            passed = await test_func()
            results.add(test_name, passed)
        except Exception as e:
            results.add(test_name, False, str(e))
            print(f"❌ Test failed with error: {e}")
    
    # Print summary
    results.print_summary()
    
    # Overall assessment
    print("\n" + "=" * 80)
    if results.passed == len(tests):
        print("🎉 ALL TESTS PASSED! System is fully operational.")
    elif results.passed >= len(tests) * 0.8:
        print("✅ Most tests passed. System is operational with minor issues.")
    elif results.passed >= len(tests) * 0.5:
        print("⚠️ Some tests failed. System needs attention.")
    else:
        print("❌ Many tests failed. System requires debugging.")
    print("=" * 80)


async def main():
    """Main entry point"""
    await run_all_tests()


if __name__ == "__main__":
    print("\n🔧 Starting Advanced Orchestration Test Suite...\n")
    asyncio.run(main())