# Finite Monkey Engine v2.0

**An AI-Powered Code Security Analysis Platform**

## 🚀 v2.0 Major Upgrades

**Finite Monkey Engine v2.0** brings significant architectural upgrades and feature enhancements:

### 🔥 Core Upgrades
- **🎯 Precision Language Support**: Focus on 4 core languages (Solidity/Rust/C++/Move) for optimal analysis experience
- **🧠 RAG Architecture Optimization**: New LanceDB merged 2-table architecture with 300% query efficiency improvement
- **📊 Intelligent Context Understanding**: Multi-dimensional embedding technology, significantly enhanced code comprehension
- **⚡ Performance Optimization**: Unified storage strategy, 50% memory reduction, improved concurrent processing
- **🔍 Deep Business Analysis**: Enhanced business flow visualization and cross-contract dependency analysis

## 🎯 Overview

Finite Monkey Engine is an advanced AI-driven code security analysis platform **focused on blockchain and system-level code security auditing**. By integrating multiple AI models and advanced static analysis techniques, it provides comprehensive, intelligent security auditing solutions for core programming language projects.

### 🌍 Multi-Language Support

Built on Tree-sitter parsing engine and function-level analysis architecture, **v2.0 focuses on 4 core languages** for optimal analysis experience:

**✅ Currently Fully Supported Languages:**
- **Solidity** (.sol) - Ethereum smart contracts with complete Tree-sitter support
- **Rust** (.rs) - Solana ecosystem, Substrate, system-level programming
- **C/C++** (.c/.cpp/.cxx/.cc/.C/.h/.hpp/.hxx) - Blockchain core, node clients
- **Move** (.move) - Aptos, Sui blockchain language
- **Go** (.go) - Blockchain infrastructure, TEE projects~~

**🔄 Planned Support (Future Versions):**
- ~~**Cairo** (.cairo) - StarkNet smart contract language~~
- ~~**Tact** (.tact) - TON blockchain smart contracts~~
- ~~**FunC** (.fc/.func) - TON blockchain native language~~
- ~~**FA** (.fr) - Functional smart contract language~~
- ~~**Python** (.py) - Web3, DeFi backend projects~~
- ~~**JavaScript/TypeScript** (.js/.ts) - Web3 frontend, Node.js projects~~
- ~~**Java** (.java) - Enterprise blockchain applications~~

> 💡 **v2.0 Design Philosophy**: Focus on core languages to provide deeply optimized analysis capabilities. Based on function-granularity code analysis architecture, theoretically extensible to any programming language. Future versions will gradually support more languages.

## 🚀 v2.0 Key Features

### 🧠 Enhanced AI-Powered Analysis
- **Multi-Model Collaboration**: Claude-4 Sonnet, GPT-4 and other AI models working intelligently together
- **RAG-Enhanced Understanding**: Multi-dimensional context-aware technology based on LanceDB
- **Deep Business Logic Analysis**: Deep understanding of DeFi protocols, governance mechanisms, and tokenomics
- **Intelligent Vulnerability Discovery**: AI-assisted complex vulnerability pattern recognition

### 🔍 Comprehensive Security Detection System
- **Precision Vulnerability Detection**: Focus on core languages for more accurate vulnerability identification
- **Cross-Contract Deep Analysis**: Multi-contract interaction analysis and complex dependency tracking
- **Business Scenario Review**: Professional security analysis for different DeFi scenarios
- **Intelligent False Positive Filtering**: AI-assisted reduction of false positives, improving analysis accuracy

### 🛠 Precision Language Architecture
- **Core Language Focus**: Specialized framework for Solidity/Rust/C++/Move languages
- **Modular Design**: Planning, validation, context, and analysis modules
- **Tree-sitter Parsing**: Advanced parsing supporting core languages with high precision

## 📁 Project Structure

```
finite-monkey-engine/
├── src/
│   ├── agentic/            # Defense-only agentic orchestration, safety, FAR, fork validation
│   ├── planning/           # Task planning and business flow analysis
│   ├── validating/         # Vulnerability detection and validation
│   ├── context/            # Context management and RAG processing
│   ├── reasoning/          # Analysis reasoning and dialogue management
│   ├── dao/                # Data access objects and entity management
│   ├── library/            # Parsing libraries and utilities
│   ├── openai_api/        # AI API integrations
│   └── prompt_factory/     # Prompt engineering and management
├── knowledges/             # Domain knowledge base
├── scripts/                # Utility scripts
└── docs/                   # Documentation
```

## 🚀 Quick Start - Enhanced Exploit Discovery

### Agentic Defense-Only Extensions

The platform now includes a defense-only agentic framework built to discover novel permissionless vulnerabilities and validate them in a forked environment. It computes a normalized funds-at-risk metric (`funds_at_risk`) in [0, 100]:

- 0: fully safe under current assumptions
- 100: completely exploitable permissionlessly for funds theft

Key modules in `src/agentic`:

- Orchestrator: coordinates planning and fork validation
- ComplexAttackPlanner: synthesizes multi-step sequences against mined invariants/intents
- ForkValidator: runs sequences on a local fork/simulator and collects artifacts
- FundsAtRiskScorer: computes `funds_at_risk` from validation artifacts or confirmation rounds

Reporting now includes a `funds_at_risk` column in the Excel generated by `ResProcessor.generate_excel`.


### Prerequisites
- **Python 3.10+**
- **PostgreSQL 13+** (required for storing analysis results)
- **AI API Keys** (supports OpenAI, Claude, DeepSeek, and other compatible services)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-org/finite-monkey-engine.git
cd finite-monkey-engine

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Configure environment variables
cp env.example .env
# Edit .env file with your API keys and database configuration

# 4. Initialize database
psql -U postgres -d postgres -f project_task.sql
```

### 🎯 NEW: Simplified Exploit Discovery Usage

```bash
# Simply provide the path to your project - that's it!
python src/main.py --path /path/to/your/project

# Advanced usage with custom settings
python src/main.py --path /path/to/your/project \
  --output my_exploit_report.xlsx \
  --scan-mode COMMON_PROJECT_FINE_GRAINED

# Generate reports from existing analysis
python src/main.py --generate-report --project-id my_project
```

### ✨ Key Improvements in v2.0

- **🎯 Real-World Exploit Discovery**: Focus on permissionless and novel complex vulnerabilities
- **📝 English-Only Interface**: All output and reports in professional English
- **🚀 Simplified Usage**: Just provide project path - no manual configuration needed
- **⚡ Enhanced CLI**: Comprehensive command-line interface with built-in help

For detailed usage instructions, see [EXPLOIT_DISCOVERY_GUIDE.md](./EXPLOIT_DISCOVERY_GUIDE.md)

## 📊 Usage Guide

### 🎯 Enhanced Command Line Interface

Finite Monkey Engine v2.0 now provides a powerful command-line interface for exploit discovery:

```bash
# Get help and see all options
python src/main.py --help

# Basic exploit discovery analysis
python src/main.py --path /path/to/your/project

# Advanced analysis with custom output
python src/main.py --path /path/to/your/project --output detailed_analysis.xlsx

# Different scanning modes
python src/main.py --path /path/to/your/project --scan-mode PURE_SCAN
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--path` | Path to project directory for analysis | None |
| `--project-id` | Custom project ID (auto-generated if not provided) | Auto-generated |
| `--mode` | Operation mode: `exploit_discovery`, `direct_excel`, `test` | `exploit_discovery` |
| `--output` | Output file path for analysis report | `./exploit_analysis_report.xlsx` |
| `--generate-report` | Generate report from existing data | False |
| `--scan-mode` | Scanning mode: `PURE_SCAN`, `COMMON_PROJECT`, `CHECKLIST`, `COMMON_PROJECT_FINE_GRAINED` | `COMMON_PROJECT_FINE_GRAINED` |

### Database Initialization

Initialize PostgreSQL database using the provided SQL file:

```bash
# Connect to PostgreSQL database
psql -U postgres -d postgres

# Execute SQL file to create table structure
\i project_task.sql

# Or use command line directly
psql -U postgres -d postgres -f project_task.sql
```

### Legacy Configuration (Optional)

For advanced users who want to use the legacy dataset-based configuration:

Configure your project in `src/dataset/agent-v1-c4/datasets.json`:

```json
{
  "your_project_id": {
    "path": "your_project_folder_name",
    "files": [],
    "functions": [],
    "exclude_in_planning": "false",
    "exclude_directory": []
  }
}
```

### Legacy Running Method

1. **Set Project ID**: Configure your project ID in `src/main.py` (if not using CLI)
2. **Execute Analysis**: `python src/main.py`
3. **View Results**: 
   - Detailed analysis records in database
   - Excel report file
   - Mermaid business flow diagrams (if enabled)

## 🔧 Configuration

### Quick Configuration

1. **Copy environment template**:
   ```bash
   cp env.example .env
   ```

2. **Edit `.env` file** with your API keys and preferences

### Core Environment Variables

```bash
# Database Configuration (Required)
DATABASE_URL=postgresql://postgres:1234@127.0.0.1:5432/postgres

# AI Model Configuration (Required)
OPENROUTER_API_BASE="openrouter.ai"  # LLM provider (OpenRouter)
OPENROUTER_API_KEY="sk-or-v1-xxxxxx"  # API key
OPENROUTER_REFERER="https://your-app.example"  # optional
OPENROUTER_TITLE="FiniteMonkey"  # optional

# Scan Mode Configuration
SCAN_MODE=COMMON_PROJECT_FINE_GRAINED   # Recommended mode: Common project checklist fine-grained
# Available modes: PURE_SCAN (Pure scanning)
SCAN_MODE_AVA=False                     # Advanced scan mode features
COMPLEXITY_ANALYSIS_ENABLED=True        # Enable complexity analysis

# Performance Tuning
MAX_THREADS_OF_SCAN=10                  # Maximum threads for scanning phase
MAX_THREADS_OF_CONFIRMATION=50          # Maximum threads for confirmation phase
BUSINESS_FLOW_COUNT=4                   # Business flow repeat count (hallucination triggers)

# Advanced Feature Configuration
ENABLE_DIALOGUE_MODE=False              # Whether to enable dialogue mode
IGNORE_FOLDERS=node_modules,build,dist,test,tests,.git  # Folders to ignore

# Checklist Configuration
CHECKLIST_PATH=src/knowledges/checklist.xlsx  # Path to checklist file
CHECKLIST_SHEET=Sheet1                  # Checklist worksheet name
```

> 📝 **Complete Configuration**: See `env.example` file for all configurable options and detailed descriptions

### AI Model Configuration Details

Based on actual configuration in `src/openai_api/model_config.json`:

**WARNING**  must set the model name based on your llm hub!
**WARNING**  must set the model name based on your llm hub!
**WARNING**  like in openrouter, sonnet 4 need to set to anthropic/sonnet-4

```json
{
  "openai_general": "gpt-4.1",
  "code_assumptions_analysis": "claude-sonnet-4-20250514",
  "vulnerability_detection": "claude-sonnet-4-20250514",
  "initial_vulnerability_validation": "deepseek-reasoner",
  "vulnerability_findings_json_extraction": "gpt-4o-mini",
  "additional_context_determination": "deepseek-reasoner",
  "comprehensive_vulnerability_analysis": "deepseek-reasoner",
  "final_vulnerability_extraction": "gpt-4o-mini",
  "structured_json_extraction": "gpt-4.1",
  "embedding_model": "text-embedding-3-large"
}
```

### Recommended Configuration Schemes

#### 🚀 Quick Start (Small projects < 50 files)
```bash
SCAN_MODE=PURE_SCAN
COMPLEXITY_ANALYSIS_ENABLED=False
MAX_THREADS_OF_SCAN=3
BUSINESS_FLOW_COUNT=2
```

#### 🏢 Enterprise (Large projects > 100 files)
```bash
SCAN_MODE=COMMON_PROJECT_FINE_GRAINED
COMPLEXITY_ANALYSIS_ENABLED=True
MAX_THREADS_OF_SCAN=8
MAX_THREADS_OF_CONFIRMATION=30
BUSINESS_FLOW_COUNT=4
```

#### 💰 Cost Optimized
```bash
SCAN_MODE=PURE_SCAN
BUSINESS_FLOW_COUNT=1
MAX_THREADS_OF_SCAN=3
MAX_THREADS_OF_CONFIRMATION=10
COMPLEXITY_ANALYSIS_ENABLED=False
```

## 🎯 Use Cases

### Blockchain & Web3 Projects
- **Smart Contract Security**: Solidity, Rust, Move contract analysis
- **DeFi Protocol Analysis**: AMM, lending, governance mechanism review
- **Cross-Chain Applications**: Bridge security, multi-chain deployment analysis
- **NFT & Gaming**: Minting logic, marketplace integration security

### Traditional Software Projects
- **Web3 Backend**: Python/Node.js API security analysis
- **Blockchain Infrastructure**: Go/C++ node and client security
- **Enterprise Applications**: Java enterprise blockchain applications
- **System-Level Code**: C/C++ core components and TEE projects

### Multi-Language Project Analysis
- **Polyglot Codebases**: Cross-language dependency analysis
- **Microservice Architecture**: Multi-service security assessment
- **Full-Stack Applications**: Frontend, backend, and contract integration security

## 📊 Analysis Reports

The platform generates comprehensive analysis reports including:

- **Security Vulnerability Report**: Detailed vulnerability findings with severity ratings
- **Business Flow Diagrams**: Visual representation of contract interactions
- **Gas Optimization Suggestions**: Performance improvement recommendations
- **Best Practice Compliance**: Adherence to security standards and guidelines

## 🧪 Testing

Run the test suite:

```bash
# Unit tests
python -m pytest tests/

# Integration tests
python -m pytest tests/integration/

# Coverage report
python -m pytest --cov=src tests/
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **ANTLR4**: For Solidity parsing capabilities
- **Claude AI**: For advanced code understanding
- **Mermaid**: For business flow visualization
- **OpenAI**: For AI-powered analysis capabilities

## 📞 Contact

- **Email**: nerbonic@gmail.com
- **Twitter**: [@xy9301](https://x.com/xy9301)
- **Telegram**: [https://t.me/+4-s4jDfy-ig1M2Y1](https://t.me/+4-s4jDfy-ig1M2Y1)

---

## 🆕 v2.0 Release Notes - Enhanced Exploit Discovery

### Major Upgrades
- **Real-World Exploit Discovery**: Focus on permissionless and novel complex vulnerabilities
- **English-Only Interface**: Professional English-only output for international use
- **Simplified CLI**: Just provide project path - no manual configuration needed
- **Enhanced AI Analysis**: Advanced vulnerability pattern recognition for complex exploits
- **Core Language Specialization**: Optimized for Solidity/Rust/C++/Move analysis
- **RAG Architecture Revolution**: LanceDB merged 2-table architecture with 300% performance improvement

### Key Improvements
- **No Manual Configuration**: Automatic project detection from path input
- **Advanced Exploit Detection**: Focus on complex DeFi, cross-chain, and governance attacks
- **Comprehensive CLI**: Full command-line interface with help documentation
- **Professional Output**: English-only logging and reporting
- **Multiple Operation Modes**: Flexible analysis modes for different use cases

### Migration Guide
- **New Usage**: `python src/main.py --path /your/project/path`
- **Legacy Support**: Old configuration methods still work
- **No Breaking Changes**: Fully backward compatible
- **Enhanced Features**: All existing functionality plus new exploit discovery capabilities

---

**🎉 Finite Monkey Engine v2.0 - Making Code Security Analysis More Intelligent, Professional, and Efficient!** 