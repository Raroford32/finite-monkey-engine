// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Test contract with multiple vulnerabilities for demonstration
 * DO NOT USE IN PRODUCTION - INTENTIONALLY VULNERABLE
 */
contract VulnerableBank {
    mapping(address => uint256) public balances;
    address public owner;
    bool public locked;
    
    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    
    constructor() {
        owner = msg.sender;
    }
    
    // Vulnerability 1: Missing access control
    function setOwner(address newOwner) public {
        owner = newOwner;
    }
    
    // Vulnerability 2: Reentrancy vulnerability
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // External call before state update (reentrancy vulnerability)
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        // State update after external call
        balances[msg.sender] -= amount;
        
        emit Withdrawal(msg.sender, amount);
    }
    
    // Vulnerability 3: Integer overflow (in Solidity < 0.8.0)
    function deposit() public payable {
        // This would overflow in older Solidity versions
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
    
    // Vulnerability 4: Unchecked return value
    function transferTo(address recipient, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        
        // Unchecked call return value
        payable(recipient).send(amount);
    }
    
    // Vulnerability 5: Front-running vulnerability
    function buyToken(uint256 price) public payable {
        require(msg.value == price, "Incorrect payment");
        // Price can be front-run
        // ... token purchase logic
    }
    
    // Vulnerability 6: Delegate call to arbitrary address
    function delegateExecute(address target, bytes memory data) public {
        // Dangerous delegatecall to user-controlled address
        (bool success, ) = target.delegatecall(data);
        require(success, "Delegatecall failed");
    }
    
    // Vulnerability 7: Timestamp dependency
    function timeLock() public view returns (bool) {
        // Miner can manipulate timestamp
        return block.timestamp % 2 == 0;
    }
    
    // Vulnerability 8: Weak randomness
    function random() public view returns (uint256) {
        // Predictable randomness
        return uint256(keccak256(abi.encodePacked(block.timestamp, block.difficulty)));
    }
    
    receive() external payable {
        deposit();
    }
}