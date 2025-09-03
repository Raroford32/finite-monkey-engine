#!/usr/bin/env python3
"""
Test script for OpenRouter.ai integration with openai/gpt-5 model

This script tests the LLM client integration to ensure it's working correctly
with the OpenRouter API.
"""

import asyncio
import sys
import os
from pathlib import Path
from dotenv import load_dotenv

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

# Load environment variables
load_dotenv()

from core.llm_client import OpenRouterClient, test_connection


async def test_llm_integration():
    """Test the complete LLM integration"""
    print("=" * 60)
    print("Testing OpenRouter.ai Integration")
    print("=" * 60)
    
    # Check environment variables
    api_key = os.getenv('OPENROUTER_API_KEY')
    if not api_key or api_key == 'your_openrouter_api_key_here':
        print("❌ Error: OPENROUTER_API_KEY not set in .env file")
        print("Please copy .env.example to .env and add your OpenRouter API key")
        return False
    
    print(f"✅ API Key configured: {api_key[:10]}...")
    print(f"✅ Model: {os.getenv('LLM_MODEL', 'openai/gpt-5')}")
    print(f"✅ API URL: {os.getenv('OPENROUTER_API_URL', 'https://openrouter.ai/api/v1')}")
    
    # Test connection
    print("\nTesting connection to OpenRouter...")
    success = await test_connection()
    
    if not success:
        print("❌ Failed to connect to OpenRouter")
        return False
    
    print("✅ Connection successful!")
    
    # Test vulnerability analysis
    print("\nTesting vulnerability analysis...")
    client = OpenRouterClient()
    
    test_code = """
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
    }
    """
    
    result = await client.analyze_vulnerability(test_code)
    
    if 'error' in result:
        print(f"❌ Analysis failed: {result['error']}")
        return False
    
    print("✅ Vulnerability analysis successful!")
    print(f"Analysis result preview: {str(result)[:200]}...")
    
    # Test hypothesis generation
    print("\nTesting exploit hypothesis generation...")
    
    hypothesis = await client.generate_exploit_hypothesis(
        vulnerability_type="reentrancy",
        target_info={
            "contract": "TestContract",
            "function": "withdraw",
            "has_external_calls": True
        }
    )
    
    if 'error' in hypothesis:
        print(f"❌ Hypothesis generation failed: {hypothesis['error']}")
        return False
    
    print("✅ Hypothesis generation successful!")
    print(f"Hypothesis preview: {str(hypothesis)[:200]}...")
    
    print("\n" + "=" * 60)
    print("✅ All tests passed! OpenRouter integration is working.")
    print("=" * 60)
    
    return True


async def main():
    """Main entry point"""
    try:
        success = await test_llm_integration()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())