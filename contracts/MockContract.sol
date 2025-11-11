// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title MockContract
 * @dev Simple mock contract for testing SimpleProxy
 */
contract MockContract {
    uint256 public value;
    
    event ValueStored(uint256 newValue);
    
    function store(uint256 _value) external {
        value = _value;
        emit ValueStored(_value);
    }
    
    function getValue() external view returns (uint256) {
        return value;
    }
    
    function transfer(address /* to */, uint256 /* amount */) external pure returns (bool) {
        // Mock transfer function
        return true;
    }
    
    receive() external payable {
        // Accept ETH
    }
}

