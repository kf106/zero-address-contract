const fs = require('fs');
const { ethers } = require('hardhat');

async function getInitCode() {
    // Read the compiled artifact
    const artifact = JSON.parse(
        fs.readFileSync('artifacts/contracts/SimpleProxy.sol/SimpleProxy.json', 'utf8')
    );
    
    // Get the bytecode (includes constructor code)
    const bytecode = artifact.bytecode;
    
    // Encode constructor arguments
    // Constructor takes: address _authorizedAddress
    // We'll use address(0) to get the default, but you can change this
    const authorizedAddress = ethers.ZeroAddress; // Will default to 0x2c36dd7Bb3E95E7a0219E70737eE8041f22d2081
    
    const iface = new ethers.Interface(artifact.abi);
    const encodedArgs = iface.encodeDeploy([authorizedAddress]);
    
    // Remove the 0x prefix from bytecode and encoded args, then combine
    const bytecodeHex = bytecode.replace('0x', '');
    const encodedArgsHex = encodedArgs.replace('0x', '');
    
    // Init code = bytecode + encoded constructor arguments (without 0x prefix for file)
    const initCodeHex = bytecodeHex + encodedArgsHex;
    const initCodeWithPrefix = '0x' + initCodeHex;
    
    console.log('Bytecode (first 100 chars):', bytecode.substring(0, 100) + '...');
    console.log('Encoded constructor args:', encodedArgs);
    console.log('Init code (first 100 chars):', initCodeWithPrefix.substring(0, 100) + '...');
    console.log('Init code length:', initCodeHex.length / 2, 'bytes');
    console.log();
    console.log('Full init code (hex with 0x prefix):');
    console.log(initCodeWithPrefix);
    
    // Save to file without 0x prefix (Python and Rust will handle it)
    fs.writeFileSync('init_code.txt', initCodeHex);
    console.log();
    console.log('Saved to init_code.txt (without 0x prefix)');
}

getInitCode().catch(console.error);

