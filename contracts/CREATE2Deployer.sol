// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title CREATE2Deployer
 * @dev Minimal contract that uses CREATE2 to deploy contracts
 * This contract is deployed from an EOA, and then uses CREATE2 to deploy the target contract
 */
contract CREATE2Deployer {
    /**
     * @dev Deploy a contract using CREATE2
     * @param bytecode The contract bytecode (including constructor args)
     * @param salt The 32-byte salt value
     * @return deployedAddress The address where the contract was deployed
     */
    function deploy(bytes memory bytecode, bytes32 salt) external returns (address deployedAddress) {
        assembly {
            deployedAddress := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }
        
        require(deployedAddress != address(0), "CREATE2 deployment failed");
        
        return deployedAddress;
    }
    
    /**
     * @dev Compute the CREATE2 address for given bytecode and salt
     * @param bytecode The contract bytecode (including constructor args)
     * @param salt The 32-byte salt value
     * @return The computed address
     */
    function computeAddress(bytes memory bytecode, bytes32 salt) public view returns (address) {
        bytes32 initCodeHash = keccak256(bytecode);
        
        return address(uint160(uint256(keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(this), // This contract's address (deployed from EOA)
                salt,
                initCodeHash
            )
        ))));
    }
}

