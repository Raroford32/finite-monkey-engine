"""
Advanced Protocol and Codebase Analyzers

This module implements sophisticated analysis capabilities:
- Protocol dependency analysis
- AST-based codebase analysis
- Pattern recognition
- Vulnerability detection
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from pathlib import Path
import networkx as nx
import ast
import re

logger = logging.getLogger(__name__)


@dataclass
class ProtocolAnalysisResult:
    """Result of protocol analysis"""
    protocol_name: str
    contracts: List[Dict[str, Any]] = field(default_factory=list)
    entry_points: List[Dict[str, Any]] = field(default_factory=list)
    state_variables: List[Dict[str, Any]] = field(default_factory=list)
    external_calls: List[Dict[str, Any]] = field(default_factory=list)
    dependencies: Dict[str, List[str]] = field(default_factory=dict)
    access_controls: List[Dict[str, Any]] = field(default_factory=list)
    invariants: List[Dict[str, Any]] = field(default_factory=list)
    risk_areas: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class CodebaseAnalysisResult:
    """Result of codebase analysis"""
    path: str
    language: str
    functions: List[Dict[str, Any]] = field(default_factory=list)
    call_graph: Dict[str, List[str]] = field(default_factory=dict)
    data_flow: Dict[str, Any] = field(default_factory=dict)
    control_flow: Dict[str, Any] = field(default_factory=dict)
    complexity_metrics: Dict[str, Any] = field(default_factory=dict)
    vulnerability_patterns: List[Dict[str, Any]] = field(default_factory=list)
    ast_tree: Optional[Any] = None


class ProtocolAnalyzer:
    """
    Advanced protocol analyzer for understanding DeFi protocols
    
    Analyzes:
    - Contract interactions and dependencies
    - State management and invariants
    - Access control mechanisms
    - External integrations
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the protocol analyzer"""
        self.config = config or {}
        self.analyze_dependencies = self.config.get('analyze_dependencies', True)
        self.track_state_changes = self.config.get('track_state_changes', True)
        self.detect_reentrancy = self.config.get('detect_reentrancy', True)
        self.analyze_access_control = self.config.get('analyze_access_control', True)
        
        # Pattern database
        self.protocol_patterns = self._initialize_protocol_patterns()
        
        logger.info("Protocol Analyzer initialized")
    
    def _initialize_protocol_patterns(self) -> Dict[str, Any]:
        """Initialize protocol-specific patterns"""
        return {
            'defi_patterns': {
                'lending': ['borrow', 'repay', 'liquidate', 'collateral'],
                'dex': ['swap', 'addLiquidity', 'removeLiquidity', 'price'],
                'yield': ['stake', 'unstake', 'harvest', 'compound'],
                'governance': ['propose', 'vote', 'execute', 'delegate']
            },
            'risk_patterns': {
                'oracle_dependency': ['getPrice', 'oracle', 'priceFeed'],
                'admin_functions': ['pause', 'unpause', 'setAdmin', 'upgrade'],
                'token_operations': ['transfer', 'approve', 'mint', 'burn']
            }
        }
    
    async def analyze(
        self,
        target: str,
        context: Optional[Dict[str, Any]] = None
    ) -> ProtocolAnalysisResult:
        """Analyze a protocol or smart contract system"""
        logger.info(f"Analyzing protocol: {target}")
        
        result = ProtocolAnalysisResult(protocol_name=target)
        
        # Phase 1: Contract discovery
        contracts = await self._discover_contracts(target, context)
        result.contracts = contracts
        
        # Phase 2: Entry point identification
        entry_points = await self._identify_entry_points(contracts)
        result.entry_points = entry_points
        
        # Phase 3: State variable analysis
        state_variables = await self._analyze_state_variables(contracts)
        result.state_variables = state_variables
        
        # Phase 4: External call analysis
        external_calls = await self._analyze_external_calls(contracts)
        result.external_calls = external_calls
        
        # Phase 5: Dependency mapping
        if self.analyze_dependencies:
            dependencies = await self._map_dependencies(contracts, external_calls)
            result.dependencies = dependencies
        
        # Phase 6: Access control analysis
        if self.analyze_access_control:
            access_controls = await self._analyze_access_controls(contracts)
            result.access_controls = access_controls
        
        # Phase 7: Invariant detection
        invariants = await self._detect_invariants(contracts, state_variables)
        result.invariants = invariants
        
        # Phase 8: Risk area identification
        risk_areas = await self._identify_risk_areas(result)
        result.risk_areas = risk_areas
        
        return result
    
    async def _discover_contracts(
        self,
        target: str,
        context: Optional[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Discover all contracts in the protocol"""
        contracts = []
        
        # Check if target is a directory
        target_path = Path(target)
        if target_path.exists() and target_path.is_dir():
            # Find all Solidity files
            for sol_file in target_path.rglob("*.sol"):
                contract_data = await self._parse_solidity_file(sol_file)
                contracts.extend(contract_data)
        
        # Add context contracts if provided
        if context and 'contracts' in context:
            contracts.extend(context['contracts'])
        
        return contracts
    
    async def _parse_solidity_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Parse a Solidity file to extract contract information"""
        contracts = []
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Simple regex-based parsing (would use proper parser in production)
            contract_pattern = r'contract\s+(\w+)(?:\s+is\s+([^{]+))?'
            matches = re.findall(contract_pattern, content)
            
            for match in matches:
                contract_name = match[0]
                inheritance = match[1].strip() if match[1] else ""
                
                contracts.append({
                    'name': contract_name,
                    'file': str(file_path),
                    'inheritance': inheritance.split(',') if inheritance else [],
                    'code': content,
                    'functions': self._extract_functions(content, contract_name),
                    'modifiers': self._extract_modifiers(content),
                    'events': self._extract_events(content)
                })
        
        except Exception as e:
            logger.error(f"Error parsing {file_path}: {e}")
        
        return contracts
    
    def _extract_functions(self, code: str, contract_name: str) -> List[Dict[str, Any]]:
        """Extract functions from contract code"""
        functions = []
        
        # Regex for function signatures
        func_pattern = r'function\s+(\w+)\s*\([^)]*\)(?:\s+(\w+(?:\s+\w+)*))?'
        matches = re.findall(func_pattern, code)
        
        for match in matches:
            func_name = match[0]
            modifiers = match[1].strip() if match[1] else ""
            
            functions.append({
                'name': func_name,
                'contract': contract_name,
                'visibility': self._extract_visibility(modifiers),
                'modifiers': modifiers.split() if modifiers else [],
                'is_payable': 'payable' in modifiers,
                'is_view': 'view' in modifiers or 'constant' in modifiers,
                'is_pure': 'pure' in modifiers
            })
        
        return functions
    
    def _extract_visibility(self, modifiers: str) -> str:
        """Extract function visibility"""
        visibilities = ['public', 'external', 'internal', 'private']
        for vis in visibilities:
            if vis in modifiers:
                return vis
        return 'public'  # Default visibility
    
    def _extract_modifiers(self, code: str) -> List[str]:
        """Extract custom modifiers from contract"""
        modifier_pattern = r'modifier\s+(\w+)'
        return re.findall(modifier_pattern, code)
    
    def _extract_events(self, code: str) -> List[str]:
        """Extract events from contract"""
        event_pattern = r'event\s+(\w+)'
        return re.findall(event_pattern, code)
    
    async def _identify_entry_points(
        self,
        contracts: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Identify protocol entry points"""
        entry_points = []
        
        for contract in contracts:
            for function in contract.get('functions', []):
                # Entry points are public/external functions
                if function['visibility'] in ['public', 'external']:
                    # Check if it's a significant entry point
                    if self._is_significant_entry_point(function):
                        entry_points.append({
                            'contract': contract['name'],
                            'function': function['name'],
                            'visibility': function['visibility'],
                            'is_payable': function['is_payable'],
                            'risk_level': self._assess_entry_point_risk(function)
                        })
        
        return entry_points
    
    def _is_significant_entry_point(self, function: Dict[str, Any]) -> bool:
        """Check if function is a significant entry point"""
        # Significant functions based on name patterns
        significant_patterns = [
            'deposit', 'withdraw', 'borrow', 'repay', 'swap',
            'stake', 'unstake', 'mint', 'burn', 'transfer',
            'liquidate', 'flashLoan', 'execute'
        ]
        
        func_name_lower = function['name'].lower()
        return any(pattern in func_name_lower for pattern in significant_patterns)
    
    def _assess_entry_point_risk(self, function: Dict[str, Any]) -> str:
        """Assess risk level of an entry point"""
        risk_score = 0
        
        # Payable functions are riskier
        if function['is_payable']:
            risk_score += 3
        
        # Functions without access control are riskier
        if not function['modifiers']:
            risk_score += 2
        
        # External functions are slightly riskier than public
        if function['visibility'] == 'external':
            risk_score += 1
        
        # Map score to risk level
        if risk_score >= 5:
            return 'high'
        elif risk_score >= 3:
            return 'medium'
        else:
            return 'low'
    
    async def _analyze_state_variables(
        self,
        contracts: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Analyze state variables in contracts"""
        state_variables = []
        
        for contract in contracts:
            code = contract.get('code', '')
            
            # Extract state variables (simplified)
            var_pattern = r'(?:mapping|address|uint\d*|int\d*|bool|bytes\d*|string)\s+(?:public\s+)?(\w+)'
            matches = re.findall(var_pattern, code)
            
            for var_name in matches:
                # Filter out function parameters and local variables
                if self._is_state_variable(var_name, code):
                    state_variables.append({
                        'name': var_name,
                        'contract': contract['name'],
                        'is_public': f'public {var_name}' in code,
                        'is_critical': self._is_critical_variable(var_name)
                    })
        
        return state_variables
    
    def _is_state_variable(self, var_name: str, code: str) -> bool:
        """Check if variable is a state variable"""
        # Simple heuristic: state variables are typically defined at contract level
        # and not inside functions
        function_pattern = r'function\s+\w+\s*\([^)]*\)[^{]*\{[^}]*' + var_name
        return not re.search(function_pattern, code)
    
    def _is_critical_variable(self, var_name: str) -> bool:
        """Check if variable is critical for security"""
        critical_patterns = [
            'owner', 'admin', 'balance', 'totalSupply',
            'paused', 'initialized', 'oracle', 'price'
        ]
        
        var_lower = var_name.lower()
        return any(pattern in var_lower for pattern in critical_patterns)
    
    async def _analyze_external_calls(
        self,
        contracts: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Analyze external calls in contracts"""
        external_calls = []
        
        for contract in contracts:
            code = contract.get('code', '')
            
            # Pattern for external calls
            call_patterns = [
                r'(\w+)\.call\(',
                r'(\w+)\.delegatecall\(',
                r'(\w+)\.staticcall\(',
                r'(\w+)\.transfer\(',
                r'(\w+)\.send\(',
                r'address\((\w+)\)\.call\('
            ]
            
            for pattern in call_patterns:
                matches = re.findall(pattern, code)
                for match in matches:
                    external_calls.append({
                        'contract': contract['name'],
                        'target': match,
                        'type': self._get_call_type(pattern),
                        'risk_level': self._assess_call_risk(pattern)
                    })
        
        return external_calls
    
    def _get_call_type(self, pattern: str) -> str:
        """Get type of external call from pattern"""
        if 'delegatecall' in pattern:
            return 'delegatecall'
        elif 'staticcall' in pattern:
            return 'staticcall'
        elif 'transfer' in pattern:
            return 'transfer'
        elif 'send' in pattern:
            return 'send'
        else:
            return 'call'
    
    def _assess_call_risk(self, pattern: str) -> str:
        """Assess risk of external call"""
        if 'delegatecall' in pattern:
            return 'critical'  # Delegatecall is very risky
        elif 'call' in pattern:
            return 'high'  # Regular call is risky
        elif 'send' in pattern:
            return 'medium'  # Send has gas limit
        else:
            return 'low'  # Transfer is relatively safe
    
    async def _map_dependencies(
        self,
        contracts: List[Dict[str, Any]],
        external_calls: List[Dict[str, Any]]
    ) -> Dict[str, List[str]]:
        """Map dependencies between contracts"""
        dependencies = {}
        
        for contract in contracts:
            contract_name = contract['name']
            deps = set()
            
            # Add inherited contracts
            deps.update(contract.get('inheritance', []))
            
            # Add contracts called externally
            for call in external_calls:
                if call['contract'] == contract_name:
                    deps.add(call['target'])
            
            dependencies[contract_name] = list(deps)
        
        return dependencies
    
    async def _analyze_access_controls(
        self,
        contracts: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Analyze access control mechanisms"""
        access_controls = []
        
        for contract in contracts:
            # Check for common access control patterns
            modifiers = contract.get('modifiers', [])
            
            for modifier in modifiers:
                if self._is_access_control_modifier(modifier):
                    # Find functions using this modifier
                    protected_functions = []
                    for function in contract.get('functions', []):
                        if modifier in function.get('modifiers', []):
                            protected_functions.append(function['name'])
                    
                    access_controls.append({
                        'contract': contract['name'],
                        'modifier': modifier,
                        'type': self._classify_access_control(modifier),
                        'protected_functions': protected_functions
                    })
        
        return access_controls
    
    def _is_access_control_modifier(self, modifier: str) -> bool:
        """Check if modifier is for access control"""
        access_patterns = ['only', 'auth', 'admin', 'owner', 'role']
        modifier_lower = modifier.lower()
        return any(pattern in modifier_lower for pattern in access_patterns)
    
    def _classify_access_control(self, modifier: str) -> str:
        """Classify type of access control"""
        modifier_lower = modifier.lower()
        
        if 'owner' in modifier_lower:
            return 'ownership'
        elif 'role' in modifier_lower:
            return 'role-based'
        elif 'pause' in modifier_lower:
            return 'pausable'
        else:
            return 'custom'
    
    async def _detect_invariants(
        self,
        contracts: List[Dict[str, Any]],
        state_variables: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Detect protocol invariants"""
        invariants = []
        
        # Common DeFi invariants
        invariant_patterns = [
            {
                'name': 'total_supply_conservation',
                'pattern': 'totalSupply',
                'description': 'Total supply should remain constant or increase monotonically'
            },
            {
                'name': 'balance_consistency',
                'pattern': 'balance',
                'description': 'Sum of balances should equal total supply'
            },
            {
                'name': 'collateralization',
                'pattern': 'collateral',
                'description': 'Loans should remain collateralized'
            }
        ]
        
        for pattern in invariant_patterns:
            # Check if pattern exists in state variables
            relevant_vars = [
                var for var in state_variables
                if pattern['pattern'] in var['name'].lower()
            ]
            
            if relevant_vars:
                invariants.append({
                    'name': pattern['name'],
                    'description': pattern['description'],
                    'variables': [var['name'] for var in relevant_vars],
                    'contracts': list(set(var['contract'] for var in relevant_vars))
                })
        
        return invariants
    
    async def _identify_risk_areas(
        self,
        result: ProtocolAnalysisResult
    ) -> List[Dict[str, Any]]:
        """Identify high-risk areas in the protocol"""
        risk_areas = []
        
        # Risk 1: Unprotected critical functions
        unprotected = []
        for entry_point in result.entry_points:
            if entry_point['risk_level'] == 'high':
                unprotected.append(entry_point)
        
        if unprotected:
            risk_areas.append({
                'type': 'unprotected_functions',
                'severity': 'high',
                'details': unprotected
            })
        
        # Risk 2: Dangerous external calls
        dangerous_calls = [
            call for call in result.external_calls
            if call['risk_level'] in ['high', 'critical']
        ]
        
        if dangerous_calls:
            risk_areas.append({
                'type': 'dangerous_external_calls',
                'severity': 'critical',
                'details': dangerous_calls
            })
        
        # Risk 3: Complex dependencies
        complex_deps = [
            (contract, deps) for contract, deps in result.dependencies.items()
            if len(deps) > 5
        ]
        
        if complex_deps:
            risk_areas.append({
                'type': 'complex_dependencies',
                'severity': 'medium',
                'details': complex_deps
            })
        
        return risk_areas


class CodebaseAnalyzer:
    """
    Advanced codebase analyzer using AST parsing
    
    Analyzes:
    - Function definitions and call graphs
    - Data flow and control flow
    - Complexity metrics
    - Vulnerability patterns
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the codebase analyzer"""
        self.config = config or {}
        self.languages = self.config.get('languages', ['solidity', 'python', 'javascript'])
        self.analyze_imports = self.config.get('analyze_imports', True)
        self.track_external_calls = self.config.get('track_external_calls', True)
        self.build_call_graph = self.config.get('build_call_graph', True)
        
        logger.info(f"Codebase Analyzer initialized for languages: {self.languages}")
    
    async def analyze(
        self,
        target: str,
        context: Optional[Dict[str, Any]] = None
    ) -> CodebaseAnalysisResult:
        """Analyze a codebase"""
        logger.info(f"Analyzing codebase: {target}")
        
        # Detect language
        language = self._detect_language(target)
        
        result = CodebaseAnalysisResult(
            path=target,
            language=language
        )
        
        # Parse based on language
        if language == 'python':
            await self._analyze_python(target, result)
        elif language == 'solidity':
            await self._analyze_solidity(target, result)
        elif language == 'javascript':
            await self._analyze_javascript(target, result)
        else:
            logger.warning(f"Unsupported language: {language}")
        
        # Build call graph if requested
        if self.build_call_graph and result.functions:
            result.call_graph = await self._build_call_graph(result.functions)
        
        # Analyze data flow
        result.data_flow = await self._analyze_data_flow(result)
        
        # Analyze control flow
        result.control_flow = await self._analyze_control_flow(result)
        
        # Calculate complexity metrics
        result.complexity_metrics = await self._calculate_complexity(result)
        
        # Detect vulnerability patterns
        result.vulnerability_patterns = await self._detect_vulnerability_patterns(result)
        
        return result
    
    def _detect_language(self, target: str) -> str:
        """Detect programming language of target"""
        target_path = Path(target)
        
        if target_path.is_file():
            ext = target_path.suffix.lower()
            if ext == '.py':
                return 'python'
            elif ext == '.sol':
                return 'solidity'
            elif ext in ['.js', '.ts']:
                return 'javascript'
        elif target_path.is_dir():
            # Check for dominant language
            py_files = list(target_path.rglob('*.py'))
            sol_files = list(target_path.rglob('*.sol'))
            js_files = list(target_path.rglob('*.js')) + list(target_path.rglob('*.ts'))
            
            if len(sol_files) > len(py_files) and len(sol_files) > len(js_files):
                return 'solidity'
            elif len(py_files) > len(js_files):
                return 'python'
            else:
                return 'javascript'
        
        return 'unknown'
    
    async def _analyze_python(
        self,
        target: str,
        result: CodebaseAnalysisResult
    ):
        """Analyze Python codebase"""
        target_path = Path(target)
        
        if target_path.is_file():
            files = [target_path]
        else:
            files = list(target_path.rglob('*.py'))
        
        for file_path in files:
            try:
                with open(file_path, 'r') as f:
                    code = f.read()
                
                # Parse AST
                tree = ast.parse(code)
                
                # Extract functions
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        func_info = {
                            'name': node.name,
                            'file': str(file_path),
                            'line': node.lineno,
                            'args': [arg.arg for arg in node.args.args],
                            'decorators': [d.id if hasattr(d, 'id') else str(d) for d in node.decorator_list],
                            'calls': self._extract_function_calls(node),
                            'complexity': self._calculate_cyclomatic_complexity(node)
                        }
                        result.functions.append(func_info)
                
                # Store AST for later analysis
                if not result.ast_tree:
                    result.ast_tree = tree
                    
            except Exception as e:
                logger.error(f"Error analyzing {file_path}: {e}")
    
    def _extract_function_calls(self, node: ast.AST) -> List[str]:
        """Extract function calls from AST node"""
        calls = []
        
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if hasattr(child.func, 'id'):
                    calls.append(child.func.id)
                elif hasattr(child.func, 'attr'):
                    calls.append(child.func.attr)
        
        return calls
    
    def _calculate_cyclomatic_complexity(self, node: ast.AST) -> int:
        """Calculate cyclomatic complexity of a function"""
        complexity = 1
        
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For)):
                complexity += 1
            elif isinstance(child, ast.ExceptHandler):
                complexity += 1
        
        return complexity
    
    async def _analyze_solidity(
        self,
        target: str,
        result: CodebaseAnalysisResult
    ):
        """Analyze Solidity codebase"""
        # Use simplified parsing (would use proper Solidity parser in production)
        target_path = Path(target)
        
        if target_path.is_file():
            files = [target_path]
        else:
            files = list(target_path.rglob('*.sol'))
        
        for file_path in files:
            try:
                with open(file_path, 'r') as f:
                    code = f.read()
                
                # Extract functions using regex
                func_pattern = r'function\s+(\w+)\s*\(([^)]*)\)'
                matches = re.findall(func_pattern, code)
                
                for func_name, params in matches:
                    func_info = {
                        'name': func_name,
                        'file': str(file_path),
                        'params': params.split(',') if params else [],
                        'visibility': self._extract_solidity_visibility(code, func_name),
                        'modifiers': self._extract_solidity_modifiers(code, func_name)
                    }
                    result.functions.append(func_info)
                    
            except Exception as e:
                logger.error(f"Error analyzing {file_path}: {e}")
    
    def _extract_solidity_visibility(self, code: str, func_name: str) -> str:
        """Extract visibility of Solidity function"""
        pattern = f'function\\s+{func_name}[^{{]*?(public|external|internal|private)'
        match = re.search(pattern, code)
        return match.group(1) if match else 'public'
    
    def _extract_solidity_modifiers(self, code: str, func_name: str) -> List[str]:
        """Extract modifiers of Solidity function"""
        pattern = f'function\\s+{func_name}[^{{]*?(?:public|external|internal|private)\\s+([^{{]*)'
        match = re.search(pattern, code)
        
        if match:
            modifiers_str = match.group(1)
            return modifiers_str.split() if modifiers_str else []
        
        return []
    
    async def _analyze_javascript(
        self,
        target: str,
        result: CodebaseAnalysisResult
    ):
        """Analyze JavaScript/TypeScript codebase"""
        # Simplified JS analysis
        target_path = Path(target)
        
        if target_path.is_file():
            files = [target_path]
        else:
            files = list(target_path.rglob('*.js')) + list(target_path.rglob('*.ts'))
        
        for file_path in files:
            try:
                with open(file_path, 'r') as f:
                    code = f.read()
                
                # Extract functions using regex
                func_patterns = [
                    r'function\s+(\w+)\s*\(',
                    r'const\s+(\w+)\s*=\s*(?:async\s+)?function',
                    r'const\s+(\w+)\s*=\s*(?:async\s+)?\('
                ]
                
                for pattern in func_patterns:
                    matches = re.findall(pattern, code)
                    for func_name in matches:
                        func_info = {
                            'name': func_name,
                            'file': str(file_path),
                            'is_async': 'async' in code[:code.find(func_name)]
                        }
                        result.functions.append(func_info)
                        
            except Exception as e:
                logger.error(f"Error analyzing {file_path}: {e}")
    
    async def _build_call_graph(
        self,
        functions: List[Dict[str, Any]]
    ) -> Dict[str, List[str]]:
        """Build function call graph"""
        call_graph = {}
        
        for func in functions:
            func_name = func['name']
            calls = func.get('calls', [])
            
            # Filter to only include defined functions
            defined_functions = {f['name'] for f in functions}
            internal_calls = [call for call in calls if call in defined_functions]
            
            call_graph[func_name] = internal_calls
        
        return call_graph
    
    async def _analyze_data_flow(
        self,
        result: CodebaseAnalysisResult
    ) -> Dict[str, Any]:
        """Analyze data flow in the codebase"""
        data_flow = {
            'tainted_variables': [],
            'data_dependencies': {},
            'sensitive_sinks': []
        }
        
        # Identify user input sources
        input_sources = self._identify_input_sources(result)
        
        # Track data flow from sources
        for source in input_sources:
            flow = self._track_data_flow(source, result)
            if flow:
                data_flow['tainted_variables'].extend(flow)
        
        # Identify sensitive sinks
        data_flow['sensitive_sinks'] = self._identify_sensitive_sinks(result)
        
        return data_flow
    
    def _identify_input_sources(
        self,
        result: CodebaseAnalysisResult
    ) -> List[Dict[str, Any]]:
        """Identify user input sources"""
        sources = []
        
        for func in result.functions:
            # Functions with parameters are potential input sources
            if func.get('args') or func.get('params'):
                sources.append({
                    'function': func['name'],
                    'type': 'parameter',
                    'inputs': func.get('args', func.get('params', []))
                })
        
        return sources
    
    def _track_data_flow(
        self,
        source: Dict[str, Any],
        result: CodebaseAnalysisResult
    ) -> List[Dict[str, Any]]:
        """Track data flow from a source"""
        # Simplified data flow tracking
        flow = []
        
        # Find functions that call the source function
        source_func = source['function']
        for func in result.functions:
            if source_func in func.get('calls', []):
                flow.append({
                    'from': source_func,
                    'to': func['name'],
                    'type': 'function_call'
                })
        
        return flow
    
    def _identify_sensitive_sinks(
        self,
        result: CodebaseAnalysisResult
    ) -> List[Dict[str, Any]]:
        """Identify sensitive operation sinks"""
        sinks = []
        sensitive_patterns = ['transfer', 'send', 'call', 'execute', 'withdraw']
        
        for func in result.functions:
            func_name_lower = func['name'].lower()
            if any(pattern in func_name_lower for pattern in sensitive_patterns):
                sinks.append({
                    'function': func['name'],
                    'file': func.get('file'),
                    'type': 'sensitive_operation'
                })
        
        return sinks
    
    async def _analyze_control_flow(
        self,
        result: CodebaseAnalysisResult
    ) -> Dict[str, Any]:
        """Analyze control flow in the codebase"""
        control_flow = {}
        
        for func in result.functions:
            func_name = func['name']
            
            # Build simplified control flow
            cfg = {
                'entry': func_name,
                'complexity': func.get('complexity', 1),
                'has_loops': self._has_loops(func),
                'has_conditionals': self._has_conditionals(func),
                'exit_points': self._count_exit_points(func)
            }
            
            control_flow[func_name] = cfg
        
        return control_flow
    
    def _has_loops(self, func: Dict[str, Any]) -> bool:
        """Check if function has loops"""
        # Simplified check
        return func.get('complexity', 1) > 3
    
    def _has_conditionals(self, func: Dict[str, Any]) -> bool:
        """Check if function has conditionals"""
        return func.get('complexity', 1) > 1
    
    def _count_exit_points(self, func: Dict[str, Any]) -> int:
        """Count exit points in function"""
        # Simplified: assume one exit point plus complexity/2
        return 1 + func.get('complexity', 1) // 2
    
    async def _calculate_complexity(
        self,
        result: CodebaseAnalysisResult
    ) -> Dict[str, Any]:
        """Calculate complexity metrics"""
        if not result.functions:
            return {}
        
        complexities = [f.get('complexity', 1) for f in result.functions]
        
        return {
            'total_functions': len(result.functions),
            'average_complexity': sum(complexities) / len(complexities),
            'max_complexity': max(complexities),
            'high_complexity_functions': [
                f['name'] for f in result.functions
                if f.get('complexity', 1) > 10
            ]
        }
    
    async def _detect_vulnerability_patterns(
        self,
        result: CodebaseAnalysisResult
    ) -> List[Dict[str, Any]]:
        """Detect vulnerability patterns in codebase"""
        patterns = []
        
        # Pattern 1: Unchecked external calls
        for func in result.functions:
            if 'call' in func.get('calls', []):
                patterns.append({
                    'type': 'unchecked_call',
                    'function': func['name'],
                    'severity': 'high'
                })
        
        # Pattern 2: Complex functions (high cyclomatic complexity)
        for func in result.functions:
            if func.get('complexity', 1) > 10:
                patterns.append({
                    'type': 'high_complexity',
                    'function': func['name'],
                    'complexity': func['complexity'],
                    'severity': 'medium'
                })
        
        # Pattern 3: Potential reentrancy
        call_graph = result.call_graph
        if call_graph:
            # Check for cycles in call graph
            G = nx.DiGraph(call_graph)
            cycles = list(nx.simple_cycles(G))
            
            for cycle in cycles:
                patterns.append({
                    'type': 'potential_reentrancy',
                    'cycle': cycle,
                    'severity': 'critical'
                })
        
        return patterns