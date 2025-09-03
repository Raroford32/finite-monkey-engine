"""
LLM Client for OpenRouter.ai Integration

This module provides a unified interface for interacting with Large Language Models
through OpenRouter.ai, specifically configured for the openai/gpt-5 model.
"""

import os
import json
import asyncio
import logging
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, field
import aiohttp
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    """Response from the LLM"""
    content: str
    model: str
    usage: Dict[str, int] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class LLMMessage:
    """Message for LLM conversation"""
    role: str  # system, user, assistant
    content: str


class OpenRouterClient:
    """
    Client for OpenRouter.ai API
    
    Provides methods for interacting with LLMs through OpenRouter,
    specifically optimized for exploit discovery and analysis tasks.
    """
    
    def __init__(self, api_key: Optional[str] = None):
        """Initialize the OpenRouter client"""
        self.api_key = api_key or os.getenv('OPENROUTER_API_KEY')
        self.api_url = os.getenv('OPENROUTER_API_URL', 'https://openrouter.ai/api/v1')
        self.model = os.getenv('LLM_MODEL', 'openai/gpt-5')
        self.temperature = float(os.getenv('LLM_TEMPERATURE', '0.7'))
        self.max_tokens = int(os.getenv('LLM_MAX_TOKENS', '4096'))
        
        if not self.api_key:
            raise ValueError("OpenRouter API key not provided. Set OPENROUTER_API_KEY environment variable.")
        
        self.headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json',
            'HTTP-Referer': 'https://github.com/aaeds',  # Required by OpenRouter
            'X-Title': 'AAEDS - Advanced Agentic Exploit Discovery System'
        }
        
        logger.info(f"OpenRouter client initialized with model: {self.model}")
    
    async def complete(
        self,
        messages: List[Union[LLMMessage, Dict[str, str]]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        stream: bool = False
    ) -> LLMResponse:
        """
        Get completion from the LLM
        
        Args:
            messages: List of messages in the conversation
            temperature: Sampling temperature (0-2)
            max_tokens: Maximum tokens to generate
            stream: Whether to stream the response
        
        Returns:
            LLMResponse with the completion
        """
        # Convert messages to dict format if needed
        formatted_messages = []
        for msg in messages:
            if isinstance(msg, LLMMessage):
                formatted_messages.append({'role': msg.role, 'content': msg.content})
            else:
                formatted_messages.append(msg)
        
        payload = {
            'model': self.model,
            'messages': formatted_messages,
            'temperature': temperature or self.temperature,
            'max_tokens': max_tokens or self.max_tokens,
            'stream': stream
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.api_url}/chat/completions",
                    headers=self.headers,
                    json=payload
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        return LLMResponse(
                            content=data['choices'][0]['message']['content'],
                            model=data['model'],
                            usage=data.get('usage', {}),
                            metadata={'finish_reason': data['choices'][0].get('finish_reason')}
                        )
                    else:
                        error_text = await response.text()
                        logger.error(f"OpenRouter API error: {response.status} - {error_text}")
                        return LLMResponse(
                            content="",
                            model=self.model,
                            error=f"API Error: {response.status} - {error_text}"
                        )
        
        except Exception as e:
            logger.error(f"Error calling OpenRouter API: {str(e)}")
            return LLMResponse(
                content="",
                model=self.model,
                error=f"Connection Error: {str(e)}"
            )
    
    async def analyze_vulnerability(
        self,
        code: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Analyze code for vulnerabilities using LLM
        
        Args:
            code: Code to analyze
            context: Additional context about the code
        
        Returns:
            Analysis results with potential vulnerabilities
        """
        system_prompt = """You are an expert security researcher specializing in smart contract and blockchain vulnerabilities.
        Analyze the provided code for potential security vulnerabilities, focusing on:
        1. Reentrancy attacks
        2. Integer overflow/underflow
        3. Access control issues
        4. Price manipulation vulnerabilities
        5. Flash loan attacks
        6. Logic errors
        7. Race conditions
        8. Front-running vulnerabilities
        
        Provide a detailed analysis with:
        - Vulnerability type
        - Severity (critical, high, medium, low)
        - Affected functions/lines
        - Attack vector
        - Potential impact
        - Proof of concept outline
        """
        
        user_prompt = f"""Analyze this code for vulnerabilities:

```
{code}
```

Context: {json.dumps(context or {}, indent=2)}

Provide your analysis in JSON format."""
        
        messages = [
            LLMMessage(role="system", content=system_prompt),
            LLMMessage(role="user", content=user_prompt)
        ]
        
        response = await self.complete(messages, temperature=0.3)
        
        if response.error:
            return {'error': response.error}
        
        try:
            # Parse JSON response
            analysis = json.loads(response.content)
            return analysis
        except json.JSONDecodeError:
            # If not valid JSON, return as text analysis
            return {'analysis': response.content}
    
    async def generate_exploit_hypothesis(
        self,
        vulnerability_type: str,
        target_info: Dict[str, Any],
        patterns: List[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Generate exploit hypothesis using LLM reasoning
        
        Args:
            vulnerability_type: Type of vulnerability to explore
            target_info: Information about the target contract/protocol
            patterns: Known vulnerability patterns
        
        Returns:
            Exploit hypothesis with attack strategy
        """
        system_prompt = """You are an advanced exploit discovery system.
        Generate detailed exploit hypotheses based on vulnerability patterns and target analysis.
        Focus on novel attack vectors and complex multi-step exploits.
        Consider economic incentives, protocol mechanics, and composability risks."""
        
        user_prompt = f"""Generate an exploit hypothesis for:

Vulnerability Type: {vulnerability_type}

Target Information:
{json.dumps(target_info, indent=2)}

Known Patterns:
{json.dumps(patterns or [], indent=2)}

Provide a detailed hypothesis including:
1. Attack vector
2. Preconditions
3. Step-by-step attack sequence
4. Expected outcome
5. Funds at risk estimation
6. Confidence level (0-1)
7. Proof of concept outline

Format as JSON."""
        
        messages = [
            LLMMessage(role="system", content=system_prompt),
            LLMMessage(role="user", content=user_prompt)
        ]
        
        response = await self.complete(messages, temperature=0.5)
        
        if response.error:
            return {'error': response.error}
        
        try:
            hypothesis = json.loads(response.content)
            return hypothesis
        except json.JSONDecodeError:
            return {'hypothesis': response.content}
    
    async def generate_poc(
        self,
        exploit_details: Dict[str, Any],
        target_language: str = "solidity"
    ) -> str:
        """
        Generate proof of concept code for an exploit
        
        Args:
            exploit_details: Details about the exploit
            target_language: Programming language for the PoC
        
        Returns:
            Proof of concept code
        """
        system_prompt = f"""You are an expert at writing proof of concept exploits.
        Generate clean, well-commented {target_language} code that demonstrates the vulnerability.
        The code should be educational and include safety checks."""
        
        user_prompt = f"""Generate a proof of concept for this exploit:

{json.dumps(exploit_details, indent=2)}

Requirements:
1. Use {target_language}
2. Include detailed comments
3. Add safety checks to prevent accidental execution
4. Make it educational and clear
5. Include setup and execution instructions

Generate the complete PoC code:"""
        
        messages = [
            LLMMessage(role="system", content=system_prompt),
            LLMMessage(role="user", content=user_prompt)
        ]
        
        response = await self.complete(messages, temperature=0.3, max_tokens=8192)
        
        if response.error:
            return f"// Error generating PoC: {response.error}"
        
        return response.content
    
    async def enhance_reasoning(
        self,
        reasoning_context: Dict[str, Any],
        hypotheses: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Enhance reasoning engine hypotheses with LLM insights
        
        Args:
            reasoning_context: Context from the reasoning engine
            hypotheses: Current hypotheses
        
        Returns:
            Enhanced hypotheses with additional insights
        """
        system_prompt = """You are part of an advanced reasoning system for exploit discovery.
        Enhance the provided hypotheses with additional insights, attack vectors, and creative approaches.
        Think like both an attacker and a defender. Consider edge cases and complex interactions."""
        
        user_prompt = f"""Enhance these vulnerability hypotheses:

Context:
{json.dumps(reasoning_context, indent=2)}

Current Hypotheses:
{json.dumps(hypotheses, indent=2)}

For each hypothesis, provide:
1. Additional attack vectors
2. Creative exploitation techniques
3. Chained exploit possibilities
4. Risk assessment
5. Mitigation bypasses

Format as JSON array of enhanced hypotheses."""
        
        messages = [
            LLMMessage(role="system", content=system_prompt),
            LLMMessage(role="user", content=user_prompt)
        ]
        
        response = await self.complete(messages, temperature=0.6)
        
        if response.error:
            logger.error(f"Failed to enhance reasoning: {response.error}")
            return hypotheses
        
        try:
            enhanced = json.loads(response.content)
            return enhanced if isinstance(enhanced, list) else hypotheses
        except json.JSONDecodeError:
            logger.warning("Failed to parse enhanced hypotheses")
            return hypotheses
    
    async def analyze_protocol_semantics(
        self,
        protocol_description: str,
        code_snippets: List[str]
    ) -> Dict[str, Any]:
        """
        Analyze protocol semantics for vulnerability patterns
        
        Args:
            protocol_description: Description of the protocol
            code_snippets: Relevant code snippets
        
        Returns:
            Semantic analysis with vulnerability insights
        """
        system_prompt = """You are an expert in DeFi protocol analysis and smart contract security.
        Analyze protocol semantics to identify complex vulnerability patterns that emerge from
        protocol mechanics, economic incentives, and composability."""
        
        code_context = "\n\n".join([f"```\n{snippet}\n```" for snippet in code_snippets])
        
        user_prompt = f"""Analyze this protocol for semantic vulnerabilities:

Protocol Description:
{protocol_description}

Code Snippets:
{code_context}

Identify:
1. Economic attack vectors
2. Governance vulnerabilities
3. Oracle manipulation risks
4. Composability issues
5. State inconsistency risks
6. MEV opportunities

Provide detailed analysis in JSON format."""
        
        messages = [
            LLMMessage(role="system", content=system_prompt),
            LLMMessage(role="user", content=user_prompt)
        ]
        
        response = await self.complete(messages, temperature=0.4)
        
        if response.error:
            return {'error': response.error}
        
        try:
            analysis = json.loads(response.content)
            return analysis
        except json.JSONDecodeError:
            return {'analysis': response.content}


# Singleton instance
_client_instance: Optional[OpenRouterClient] = None


def get_llm_client() -> OpenRouterClient:
    """Get or create the LLM client singleton"""
    global _client_instance
    if _client_instance is None:
        _client_instance = OpenRouterClient()
    return _client_instance


async def test_connection():
    """Test the OpenRouter connection"""
    client = get_llm_client()
    
    test_message = [
        LLMMessage(role="system", content="You are a helpful assistant."),
        LLMMessage(role="user", content="Say 'Connection successful!' if you can read this.")
    ]
    
    response = await client.complete(test_message, max_tokens=50)
    
    if response.error:
        logger.error(f"Connection test failed: {response.error}")
        return False
    
    logger.info(f"Connection test successful: {response.content}")
    return True


if __name__ == "__main__":
    # Test the client
    async def main():
        success = await test_connection()
        if success:
            print("✅ OpenRouter client is working correctly!")
        else:
            print("❌ Failed to connect to OpenRouter")
    
    asyncio.run(main())