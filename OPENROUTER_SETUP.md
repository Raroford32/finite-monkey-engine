# OpenRouter.ai Integration Setup Guide

## Overview

This system has been configured to use **OpenRouter.ai** as the exclusive LLM provider with the **openai/gpt-5** model for enhanced exploit discovery and analysis.

## Features

The OpenRouter integration enhances the system with:

- **LLM-Enhanced Reasoning**: Generates sophisticated vulnerability hypotheses using GPT-5
- **Intelligent PoC Generation**: Creates detailed proof-of-concept exploits
- **Semantic Analysis**: Deep understanding of protocol mechanics and vulnerabilities
- **Pattern Recognition**: Learns from previous exploits to identify new attack vectors

## Setup Instructions

### 1. Get OpenRouter API Key

1. Sign up at [OpenRouter.ai](https://openrouter.ai)
2. Navigate to your API Keys section
3. Create a new API key
4. Copy the API key

### 2. Configure Environment

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env and add your OpenRouter API key
nano .env  # or use your preferred editor
```

Update the following in your `.env` file:
```env
OPENROUTER_API_KEY=your_actual_api_key_here
LLM_MODEL=openai/gpt-5
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Test the Integration

Run the test script to verify everything is working:

```bash
python test_openrouter.py
```

You should see:
```
✅ API Key configured
✅ Connection successful!
✅ Vulnerability analysis successful!
✅ Hypothesis generation successful!
✅ All tests passed! OpenRouter integration is working.
```

## Configuration Options

The LLM integration can be configured through environment variables or config files:

### Environment Variables (.env)

```env
# Required
OPENROUTER_API_KEY=your_api_key

# Optional (with defaults)
OPENROUTER_API_URL=https://openrouter.ai/api/v1
LLM_MODEL=openai/gpt-5
LLM_TEMPERATURE=0.7
LLM_MAX_TOKENS=4096
```

### Configuration File (config.json)

```json
{
  "reasoning": {
    "enable_llm": true
  },
  "execution": {
    "enable_llm_poc": true
  },
  "llm": {
    "provider": "openrouter",
    "model": "openai/gpt-5",
    "temperature": 0.7,
    "max_tokens": 4096,
    "enable_reasoning_enhancement": true,
    "enable_poc_generation": true,
    "enable_semantic_analysis": true
  }
}
```

## Usage Examples

### Basic Analysis with LLM

```bash
# Analyze a smart contract with LLM-enhanced reasoning
python main.py 0x1234567890abcdef... --type contract --deep

# Analyze a protocol with semantic understanding
python main.py /path/to/protocol --type protocol --config config.json
```

### Programmatic Usage

```python
from core.llm_client import get_llm_client

# Get the LLM client
client = get_llm_client()

# Analyze code for vulnerabilities
result = await client.analyze_vulnerability(
    code="contract code here",
    context={"protocol": "DeFi"}
)

# Generate exploit hypothesis
hypothesis = await client.generate_exploit_hypothesis(
    vulnerability_type="reentrancy",
    target_info={"contract": "0x..."}
)

# Generate proof of concept
poc = await client.generate_poc(
    exploit_details=exploit_data,
    target_language="solidity"
)
```

## LLM Integration Architecture

The system integrates OpenRouter at multiple levels:

1. **Reasoning Engine** (`src/core/reasoning.py`)
   - Enhances vulnerability hypotheses with LLM insights
   - Generates novel attack vectors using GPT-5
   - Validates and ranks hypotheses

2. **Execution Engine** (`src/core/execution.py`)
   - Generates sophisticated PoC code
   - Creates attack sequences
   - Optimizes exploit paths

3. **LLM Client** (`src/core/llm_client.py`)
   - Manages OpenRouter API communication
   - Handles retries and error recovery
   - Provides specialized prompts for security analysis

## Cost Optimization

To manage API costs:

1. **Hypothesis Limiting**: Only top 10 hypotheses are enhanced with LLM
2. **Caching**: Results are cached to avoid duplicate API calls
3. **Fallback Mode**: System works without LLM if API is unavailable
4. **Token Management**: Configurable max tokens per request

## Troubleshooting

### API Key Issues
```
❌ Error: OPENROUTER_API_KEY not set in .env file
```
**Solution**: Ensure `.env` file exists and contains valid API key

### Connection Errors
```
❌ Failed to connect to OpenRouter
```
**Solution**: Check internet connection and API key validity

### Model Not Available
```
API Error: 404 - Model not found
```
**Solution**: Verify model name is correct (openai/gpt-5) and you have access

### Rate Limiting
```
API Error: 429 - Rate limit exceeded
```
**Solution**: Reduce request frequency or upgrade OpenRouter plan

## Security Notes

- **Never commit `.env` file** to version control
- **API keys are sensitive** - rotate regularly
- **Monitor usage** to detect unusual activity
- **Use read-only keys** when possible

## Support

For issues with:
- **OpenRouter API**: Contact support@openrouter.ai
- **System Integration**: Open an issue on GitHub
- **Configuration**: Check this guide and `.env.example`

## Future Enhancements

Planned improvements for LLM integration:

- [ ] Streaming responses for real-time analysis
- [ ] Multi-model ensemble for better accuracy
- [ ] Fine-tuned models for security analysis
- [ ] Automated prompt optimization
- [ ] Cost tracking and budgeting

---

**Note**: The system is fully functional without LLM integration but will have reduced capabilities in hypothesis generation and PoC creation. LLM integration significantly enhances the quality and creativity of exploit discovery.