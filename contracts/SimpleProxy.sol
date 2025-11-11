// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title SimpleProxy
 * @dev Simple proxy contract that forwards calls to any contract.
 * Uses `call` so the target contract sees msg.sender = proxy address.
 * Only the authorized address can execute calls.
 */
contract SimpleProxy {
    // Authorized address that can execute commands through this proxy
    address public authorizedAddress;
    
    // Events
    event AuthorizedAddressUpdated(address indexed oldAddress, address indexed newAddress);
    event CallExecuted(address indexed target, bytes data, bool success, bytes result);
    event ETHWithdrawn(address indexed to, uint256 amount);
    
    /**
     * @dev Modifier to ensure only the authorized address can execute functions
     */
    modifier onlyAuthorized() {
        require(msg.sender == authorizedAddress, "SimpleProxy: Unauthorized caller");
        _;
    }
    
    /**
     * @dev Constructor - sets the initial authorized address
     * @param _authorizedAddress The initial authorized address (defaults to 0x2c36dd7bb3e95e7a0219e70737ee8041f22d2081 if address(0))
     */
    constructor(address _authorizedAddress) {
        // Default to the original authorized address if not provided
        if (_authorizedAddress == address(0)) {
            authorizedAddress = 0x2c36dd7Bb3E95E7a0219E70737eE8041f22d2081;
        } else {
            authorizedAddress = _authorizedAddress;
        }
    }
    
    /**
     * @dev Update the authorized address
     * @param _newAuthorizedAddress The new authorized address
     */
    function setAuthorizedAddress(address _newAuthorizedAddress) external onlyAuthorized {
        require(_newAuthorizedAddress != address(0), "SimpleProxy: Invalid authorized address");
        address oldAddress = authorizedAddress;
        authorizedAddress = _newAuthorizedAddress;
        emit AuthorizedAddressUpdated(oldAddress, _newAuthorizedAddress);
    }
    
    /**
     * @dev Execute a call to any contract address
     * @param target The contract address to call
     * @param data The calldata to send
     * @return success Whether the call succeeded
     * @return result The return data from the contract
     */
    function executeTo(address target, bytes calldata data) 
        external 
        onlyAuthorized 
        returns (bool success, bytes memory result) 
    {
        require(target != address(0), "SimpleProxy: Invalid target");
        
        (success, result) = target.call(data);
        
        emit CallExecuted(target, data, success, result);
        
        return (success, result);
    }
    
    /**
     * @dev Execute a call with value (ETH) to any contract
     * @param target The contract address to call
     * @param data The calldata to send
     * @param value The amount of ETH to send (in wei)
     * @return success Whether the call succeeded
     * @return result The return data from the contract
     */
    function executeToWithValue(
        address target,
        bytes calldata data,
        uint256 value
    ) 
        external 
        onlyAuthorized 
        returns (bool success, bytes memory result) 
    {
        require(target != address(0), "SimpleProxy: Invalid target");
        require(address(this).balance >= value, "SimpleProxy: Insufficient balance");
        
        (success, result) = target.call{value: value}(data);
        
        emit CallExecuted(target, data, success, result);
        
        return (success, result);
    }
    
    /**
     * @dev Withdraw all ETH from the proxy to the authorized address
     */
    function withdrawAllETH() external onlyAuthorized {
        uint256 balance = address(this).balance;
        require(balance > 0, "SimpleProxy: No ETH to withdraw");
        
        (bool success, ) = authorizedAddress.call{value: balance}("");
        require(success, "SimpleProxy: ETH withdrawal failed");
        
        emit ETHWithdrawn(authorizedAddress, balance);
    }
    
    /**
     * @dev Receive function to accept ETH
     */
    receive() external payable onlyAuthorized {
        // Accept ETH from authorized address
    }
}

