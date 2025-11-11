const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("SimpleProxy", function () {
  let simpleProxy;
  let owner;
  let authorizedAddress;
  let otherAccount;
  let mockContract;
  
  // Default authorized address from contract
  const DEFAULT_AUTHORIZED = "0x2c36dd7bb3e95e7a0219e70737ee8041f22d2081";

  beforeEach(async function () {
    [owner, authorizedAddress, otherAccount] = await ethers.getSigners();
    
    // Deploy SimpleProxy with custom authorized address (use owner for testing)
    const SimpleProxy = await ethers.getContractFactory("SimpleProxy");
    simpleProxy = await SimpleProxy.deploy(owner.address);
    
    // Deploy a simple mock contract for testing
    const MockContract = await ethers.getContractFactory("MockContract");
    mockContract = await MockContract.deploy();
  });

  describe("Deployment", function () {
    it("Should set the default authorized address if zero address is provided", async function () {
      const SimpleProxy = await ethers.getContractFactory("SimpleProxy");
      const defaultProxy = await SimpleProxy.deploy(ethers.ZeroAddress);
      const authorized = await defaultProxy.authorizedAddress();
      expect(authorized.toLowerCase()).to.equal(DEFAULT_AUTHORIZED.toLowerCase());
    });

    it("Should set custom authorized address if provided", async function () {
      expect(await simpleProxy.authorizedAddress()).to.equal(owner.address);
    });
  });

  describe("Authorization", function () {
    it("Should allow authorized address to call executeTo", async function () {
      const MockContract = await ethers.getContractFactory("MockContract");
      const mock = await MockContract.deploy();
      
      // Encode function call
      const iface = new ethers.Interface(["function store(uint256)"]);
      const data = iface.encodeFunctionData("store", [42]);
      
      // Call from authorized address (owner)
      await expect(simpleProxy.connect(owner).executeTo(mock.target, data))
        .to.emit(simpleProxy, "CallExecuted");
      
      // Verify the call went through (mock contract should have value = 42)
      expect(await mock.getValue()).to.equal(42);
    });

    it("Should revert unauthorized calls to executeTo", async function () {
      const data = "0x";
      
      await expect(
        simpleProxy.connect(otherAccount).executeTo(mockContract.target, data)
      ).to.be.revertedWith("SimpleProxy: Unauthorized caller");
    });

    it("Should allow changing authorized address from current authorized", async function () {
      await expect(simpleProxy.connect(owner).setAuthorizedAddress(authorizedAddress.address))
        .to.emit(simpleProxy, "AuthorizedAddressUpdated")
        .withArgs(owner.address, authorizedAddress.address);
      
      expect(await simpleProxy.authorizedAddress()).to.equal(authorizedAddress.address);
    });

    it("Should revert unauthorized address change", async function () {
      await expect(
        simpleProxy.connect(otherAccount).setAuthorizedAddress(otherAccount.address)
      ).to.be.revertedWith("SimpleProxy: Unauthorized caller");
    });

    it("Should revert if setting authorized address to zero", async function () {
      await expect(
        simpleProxy.connect(owner).setAuthorizedAddress(ethers.ZeroAddress)
      ).to.be.revertedWith("SimpleProxy: Invalid authorized address");
    });
  });

  describe("ETH Management", function () {
    it("Should accept ETH from authorized address", async function () {
      const amount = ethers.parseEther("1.0");
      
      // Send ETH from authorized address
      await expect(
        owner.sendTransaction({ to: simpleProxy.target, value: amount })
      ).to.not.be.reverted;
      
      expect(await ethers.provider.getBalance(simpleProxy.target)).to.equal(amount);
    });

    it("Should revert ETH from unauthorized address", async function () {
      const amount = ethers.parseEther("1.0");
      
      // Try to send ETH from unauthorized address
      // The receive function checks onlyAuthorized, so this should revert
      await expect(
        otherAccount.sendTransaction({ to: simpleProxy.target, value: amount })
      ).to.be.reverted;
    });

    it("Should allow withdrawing ETH to authorized address", async function () {
      const amount = ethers.parseEther("1.0");
      
      // Send ETH first
      await owner.sendTransaction({ to: simpleProxy.target, value: amount });
      
      const balanceBefore = await ethers.provider.getBalance(owner.address);
      
      // Withdraw
      const tx = await simpleProxy.connect(owner).withdrawAllETH();
      const receipt = await tx.wait();
      const gasUsed = receipt.gasUsed * receipt.gasPrice;
      
      const balanceAfter = await ethers.provider.getBalance(owner.address);
      
      // Should receive the ETH (minus gas)
      expect(balanceAfter).to.be.closeTo(balanceBefore + amount - gasUsed, ethers.parseEther("0.01"));
      
      // Proxy should have no ETH left
      expect(await ethers.provider.getBalance(simpleProxy.target)).to.equal(0);
      
      // Check event
      await expect(tx).to.emit(simpleProxy, "ETHWithdrawn").withArgs(owner.address, amount);
    });

    it("Should revert unauthorized withdrawal", async function () {
      await expect(
        simpleProxy.connect(otherAccount).withdrawAllETH()
      ).to.be.revertedWith("SimpleProxy: Unauthorized caller");
    });

    it("Should revert withdrawal if no ETH", async function () {
      await expect(
        simpleProxy.connect(owner).withdrawAllETH()
      ).to.be.revertedWith("SimpleProxy: No ETH to withdraw");
    });
  });

  describe("executeTo", function () {
    it("Should revert if target is zero address", async function () {
      const data = "0x";
      
      await expect(
        simpleProxy.connect(owner).executeTo(ethers.ZeroAddress, data)
      ).to.be.revertedWith("SimpleProxy: Invalid target");
    });

    it("Should emit CallExecuted event", async function () {
      const iface = new ethers.Interface(["function getValue() returns (uint256)"]);
      const data = iface.encodeFunctionData("getValue");
      
      const tx = await simpleProxy.connect(owner).executeTo(mockContract.target, data);
      await expect(tx).to.emit(simpleProxy, "CallExecuted");
    });

    it("Should forward calls correctly", async function () {
      const MockContract = await ethers.getContractFactory("MockContract");
      const mock = await MockContract.deploy();
      
      // Store a value through the proxy
      const iface = new ethers.Interface(["function store(uint256)"]);
      const data = iface.encodeFunctionData("store", [123]);
      
      await simpleProxy.connect(owner).executeTo(mock.target, data);
      
      // Verify the value was stored
      expect(await mock.getValue()).to.equal(123);
    });
  });

  describe("executeToWithValue", function () {
    it("Should send ETH with call", async function () {
      const amount = ethers.parseEther("1.0");
      
      // Send ETH to proxy first
      await owner.sendTransaction({ to: simpleProxy.target, value: amount });
      
      // Get initial balance
      const initialBalance = await ethers.provider.getBalance(mockContract.target);
      
      // Call with value - use empty data to trigger receive() function
      const data = "0x";
      
      await expect(
        simpleProxy.connect(owner).executeToWithValue(
          mockContract.target,
          data,
          amount
        )
      ).to.emit(simpleProxy, "CallExecuted");
      
      // Mock contract should have received the ETH
      const finalBalance = await ethers.provider.getBalance(mockContract.target);
      expect(finalBalance).to.equal(initialBalance + amount);
    });

    it("Should revert if insufficient balance", async function () {
      const data = "0x";
      const value = ethers.parseEther("1.0");
      
      await expect(
        simpleProxy.connect(owner).executeToWithValue(
          mockContract.target,
          data,
          value
        )
      ).to.be.revertedWith("SimpleProxy: Insufficient balance");
    });

    it("Should revert if target is zero address", async function () {
      const amount = ethers.parseEther("1.0");
      await owner.sendTransaction({ to: simpleProxy.target, value: amount });
      
      await expect(
        simpleProxy.connect(owner).executeToWithValue(
          ethers.ZeroAddress,
          "0x",
          amount
        )
      ).to.be.revertedWith("SimpleProxy: Invalid target");
    });

    it("Should revert unauthorized calls", async function () {
      await expect(
        simpleProxy.connect(otherAccount).executeToWithValue(
          mockContract.target,
          "0x",
          ethers.parseEther("0.1")
        )
      ).to.be.revertedWith("SimpleProxy: Unauthorized caller");
    });
  });
});

