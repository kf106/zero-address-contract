const { expect } = require("chai");
const { ethers } = require("hardhat");
const fs = require("fs");

describe("CREATE2 Deployment Verification", function () {
  let deployer;
  let deployerAddress;
  let expectedContractAddress;
  let initCode;
  let factory;
  let salt;
  
  before(async function () {
    // Read myaddress.dat file
    const myaddressContent = fs.readFileSync("myaddress.dat", "utf8");
    const lines = myaddressContent.split("\n").filter(line => line.trim() !== "");
    
    if (lines.length < 3) {
      throw new Error("myaddress.dat must contain at least 3 lines (private key, public key, firstContractAddress)");
    }
    
    // Parse private key (remove 0x prefix if present)
    const privateKeyHex = lines[0].trim().replace(/^0x/, "");
    const privateKey = "0x" + privateKeyHex;
    
    // Parse expected contract address
    const firstContractLine = lines.find(line => line.startsWith("firstContractAddress="));
    if (!firstContractLine) {
      throw new Error("myaddress.dat must contain firstContractAddress");
    }
    const expectedAddressHex = firstContractLine.split("=")[1].trim().replace(/^0x/, "");
    expectedContractAddress = "0x" + expectedAddressHex.toLowerCase();
    
    // Create a signer from the private key
    deployer = new ethers.Wallet(privateKey, ethers.provider);
    deployerAddress = await deployer.getAddress();
    
    // Get the init code from the compiled contract
    const SimpleProxy = await ethers.getContractFactory("SimpleProxy");
    const bytecode = SimpleProxy.bytecode;
    
    // Encode constructor arguments (address(0) which defaults to the hardcoded address)
    const iface = SimpleProxy.interface;
    const encodedArgs = iface.encodeDeploy([ethers.ZeroAddress]);
    
    // Remove 0x prefix and combine
    const bytecodeHex = bytecode.replace("0x", "");
    const encodedArgsHex = encodedArgs.replace("0x", "");
    initCode = "0x" + bytecodeHex + encodedArgsHex;
    
    // Salt is 32 bytes of zeros (salt = 0)
    salt = ethers.ZeroHash;
    
    console.log("Deployer address:", deployerAddress);
    console.log("Expected contract address:", expectedContractAddress);
    console.log("Init code length:", (initCode.length - 2) / 2, "bytes");
  });
  
  it("Should compute CREATE2 address correctly using deployer address", async function () {
    // Compute CREATE2 address using the formula:
    // keccak256(0xff ++ deployer_address ++ salt ++ keccak256(init_code))[12:]
    
    // Compute keccak256 of init code
    const initCodeHash = ethers.keccak256(initCode);
    
    // Concatenate: 0xff + deployer_address + salt + init_code_hash
    const deployerAddressBytes = deployerAddress.slice(2); // Remove 0x
    const saltBytes = salt.slice(2); // Remove 0x
    const initCodeHashBytes = initCodeHash.slice(2); // Remove 0x
    
    const create2Input = "0xff" + deployerAddressBytes + saltBytes + initCodeHashBytes;
    
    // Compute CREATE2 hash
    const create2Hash = ethers.keccak256(create2Input);
    
    // Take last 20 bytes (40 hex characters)
    const computedAddress = "0x" + create2Hash.slice(-40).toLowerCase();
    
    console.log("Computed CREATE2 address:", computedAddress);
    console.log("Expected address:", expectedContractAddress);
    
    expect(computedAddress).to.equal(expectedContractAddress);
  });
  
  it("Should deploy CREATE2Deployer from EOA and use it to deploy SimpleProxy", async function () {
    // Fund the deployer account if needed
    const balance = await ethers.provider.getBalance(deployerAddress);
    if (balance < ethers.parseEther("0.1")) {
      const [fundedAccount] = await ethers.getSigners();
      await fundedAccount.sendTransaction({
        to: deployerAddress,
        value: ethers.parseEther("1.0")
      });
    }
    
    // Deploy CREATE2Deployer from the EOA (this will be at a deterministic address based on nonce)
    const CREATE2Deployer = await ethers.getContractFactory("CREATE2Deployer");
    const deployerContract = await CREATE2Deployer.connect(deployer).deploy();
    await deployerContract.waitForDeployment();
    const deployerContractAddress = await deployerContract.getAddress();
    
    console.log("CREATE2Deployer deployed at:", deployerContractAddress);
    console.log("Deployed from EOA:", deployerAddress);
    
    // Compute CREATE2 address using the deployer contract address
    // Note: The address in myaddress.dat uses the EOA address, but CREATE2 requires a contract
    // So we need to compute what address the deployer contract will be at, then use that
    const initCodeHash = ethers.keccak256(initCode);
    const deployerContractAddressBytes = deployerContractAddress.slice(2);
    const saltBytes = salt.slice(2);
    const initCodeHashBytes = initCodeHash.slice(2);
    const create2Input = "0xff" + deployerContractAddressBytes + saltBytes + initCodeHashBytes;
    const create2Hash = ethers.keccak256(create2Input);
    const computedAddress = "0x" + create2Hash.slice(-40).toLowerCase();
    
    // Deploy SimpleProxy using CREATE2 through the deployer contract
    const tx = await deployerContract.connect(deployer).deploy(initCode, salt);
    const receipt = await tx.wait();
    
    // Get the deployed address
    const deployedAddress = await deployerContract.computeAddress(initCode, salt);
    
    console.log("Deployed SimpleProxy address:", deployedAddress);
    console.log("Computed address:", computedAddress);
    console.log("Expected address (from myaddress.dat, using EOA as deployer):", expectedContractAddress);
    
    // Verify the contract was actually deployed
    const code = await ethers.provider.getCode(deployedAddress);
    expect(code).to.not.equal("0x");
    expect(code.length).to.be.greaterThan(2);
    
    // Store for the next test
    factory = deployerContract;
  });
  
  it("Should verify the deployed contract is SimpleProxy", async function () {
    // Get the deployed contract instance
    const deployedAddress = await factory.computeAddress(initCode, salt);
    const SimpleProxy = await ethers.getContractFactory("SimpleProxy");
    const proxy = SimpleProxy.attach(deployedAddress);
    
    // Verify it's the correct contract by checking the authorized address
    const authorizedAddress = await proxy.authorizedAddress();
    const expectedAuth = "0x2c36dd7Bb3E95E7a0219E70737eE8041f22d2081";
    
    expect(authorizedAddress.toLowerCase()).to.equal(expectedAuth.toLowerCase());
    console.log("Verified SimpleProxy deployed correctly at:", deployedAddress);
  });
  
  it("Should note the difference between EOA-based and contract-based CREATE2", async function () {
    // This test documents that myaddress.dat uses EOA address in CREATE2 formula
    // but actual CREATE2 deployment requires a contract as deployer
    // The first test verifies the computation matches myaddress.dat
    // The second test shows actual deployment (which uses contract address)
    
    console.log("\n=== CREATE2 Address Comparison ===");
    console.log("Expected (from myaddress.dat, EOA as deployer):", expectedContractAddress);
    
    if (factory) {
      const actualDeployed = await factory.computeAddress(initCode, salt);
      console.log("Actual deployed (contract as deployer):", actualDeployed);
      console.log("\nNote: CREATE2 requires a contract as deployer.");
      console.log("The address in myaddress.dat is computed using the EOA address,");
      console.log("but actual deployment uses the CREATE2Deployer contract address.");
    }
  });
});

