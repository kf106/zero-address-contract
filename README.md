# Zero Address Contract - CREATE2 Address Generator

This program generates an ECDSA private key, derives the public key and Ethereum address, then computes the CREATE2 contract address for a contract deployed with salt 0. It then starts iterating the salt, storing the resulting contract address with the most trailing zeros.

## Performance

**Rust version (recommended)**: Fastest, compiled binary with excellent performance (~10-100x faster than Python)

**Python version**: Easier to modify, good for prototyping

## Requirements

### Rust Version (Recommended)
- Rust 1.70+ (install from [rustup.rs](https://rustup.rs/))

### Python Version
- Python 3.7+
- Required packages (install via `pip install -r requirements.txt`)

## Installation & Usage

### Rust Version (Fastest)
```bash
cargo build --release
cargo run --release
```

### Python Version

It's recommended to use a Python virtual environment to keep dependencies isolated:

```bash
# Create a virtual environment
python3 -m venv venv

# Activate the virtual environment
# On Linux/macOS:
source venv/bin/activate
# On Windows:
# venv\Scripts\activate

# Install required packages
pip install -r requirements.txt

# Run the program
python generate_address.py
```

When you're done, you can deactivate the virtual environment:
```bash
deactivate
```

**Note**: The `venv/` directory is already in `.gitignore` and won't be committed to version control.

## Command-Line Options

### `-t` / `--time-estimate`

Calculate and report the expected time in millennia to find a zero address (an address where all 20 bytes are `0x00`).

```bash
# Rust version
cargo run --release -- -t

# Python version
python generate_address.py -t
```

This option:
- Benchmarks the computation speed by running 100,000 CREATE2 address calculations
- Calculates the expected time based on the probability of finding a zero address (1 in 2^160)
- Reports the result in millennia, along with a comparison to the age of the universe

**Note**: Finding a zero address is computationally infeasible - the expected time is astronomically large (many orders of magnitude longer than the age of the universe).

## What it does

1. **Loads or Generates ECDSA Key Pair**: 
   - Checks for `myaddress.dat` file
   - If it exists: loads the private and public keys, verifies they match
   - If it doesn't exist: generates a new 256-bit private key, derives the public key, and saves both to `myaddress.dat`
2. **Derives Ethereum Address**: Computes the Ethereum address from the public key (last 20 bytes of Keccak-256 hash)
3. **Searches for CREATE2 Address with Most Trailing Zeros**: 
   - Loops through incrementing 32-byte salt values (starting from `0x00…00`)
   - For each salt, computes the CREATE2 contract address using the formula:
     ```
     keccak256(0xff ++ deployer_address ++ salt ++ keccak256(init_code))[12:]
     ```
   - Tracks the salt that produces the address with the most trailing zero bytes
   - The CREATE2 address uses the last 20 bytes of the hash result

**Note**: The `myaddress.dat` file contains your private key. Keep it secure and never commit it to version control!

## CREATE2 Formula

The CREATE2 address is computed as:
- `0xff` (1 byte) + deployer address (20 bytes) + salt (32 bytes) + init code hash (32 bytes)
- The result is hashed with Keccak-256, and the last 20 bytes form the contract address

## Customization

To compute the CREATE2 address for a specific contract, modify the `init_code` variable in the `main()` function with your contract's bytecode and constructor arguments.

## Example Output

```
======================================================================
ECDSA Key Generation and CREATE2 Address Search
======================================================================

Step 1: Loading or generating ECDSA key pair...
myaddress.dat not found
Generating new key pair...
Saved keys to myaddress.dat
Generated new key pair
Private Key (hex): 0x...
Public Key (hex):  0x...

Step 2: Deriving Ethereum address from public key...
Deployer Address: 0x...

Step 3: Searching for CREATE2 address with most trailing zeros...
Searching through salt values...
Current best: 0 trailing zeros at salt 0x0000...0000
New best: 1 trailing zeros at salt 0x0000...3039 -> 0x...
New best: 2 trailing zeros at salt 0x0000...10932 -> 0x...
...

Results:
======================================================================
Private Key:      0x...
Deployer Address: 0x...
Best Salt:        0x0000...10932
Trailing Zeros:   2 bytes
CREATE2 Address:  0x...
Address (hex):    0x...
Searched through 1,000,000 salt values
```

The program will continue searching until interrupted (Ctrl+C) or until it finds an address with 20 trailing zeros (extremely unlikely). You can uncomment the search limit in the code to set a maximum number of salts to check.

## Proxy Contract

### `SimpleProxy.sol`
A simple proxy contract that forwards calls to any contract:
- Only accepts calls from an authorized address (defaults to `0x2c36dd7bb3e95e7a0219e70737ee8041f22d2081`, but can be changed)
- Can call **any contract** with **any function** on your behalf
- Uses `call` so the target contract sees `msg.sender = proxy address` (not your EOA)
- Allows changing the authorized address (only by the current authorized address)
- Includes ETH withdrawal functionality to send ETH to the authorized address

**Key Features:**
- **Universal Caller**: Call any contract via `executeTo(target, calldata)`
- **Transparent**: Target contracts see calls as coming from the proxy address
- **Simple**: Minimal code, easy to understand and audit
- **Flexible Authorization**: Change the authorized address via `setAuthorizedAddress()`
- **ETH Management**: Withdraw all ETH from the proxy via `withdrawAllETH()`

**Usage:**

```solidity
// 1. Deploy the proxy
// If _authorizedAddress is address(0), defaults to 0x2c36dd7bb3e95e7a0219e70737ee8041f22d2081
SimpleProxy proxy = new SimpleProxy(address(0));

// 2. Call any contract function (encode calldata off-chain)
// Example: Transfer ERC20 tokens
bytes memory transferData = abi.encodeWithSignature("transfer(address,uint256)", recipient, amount);
proxy.executeTo(tokenAddress, transferData);

// 3. Call with ETH value
bytes memory depositData = abi.encodeWithSignature("deposit()");
proxy.executeToWithValue(contractAddress, depositData, 1 ether);

// 4. Change the authorized address (only from current authorized address)
proxy.setAuthorizedAddress(newAuthorizedAddress);

// 5. Withdraw all ETH from the proxy to the authorized address
proxy.withdrawAllETH();
```

**Important Notes:**
- Target contracts see `msg.sender = proxy address` (not your EOA)
- Tokens/assets must be in the proxy's balance for transfers to work
- You encode function calls off-chain (using web3.js, ethers.js, etc.) and pass the calldata
- The proxy acts as a universal caller on your behalf
- The authorized address can be changed by the current authorized address
- ETH can be withdrawn to the authorized address at any time

### Using with CREATE2 Address Generator

To compute the CREATE2 address for deploying these contracts:

1. Compile the contract to get the bytecode
2. Include constructor arguments (e.g., target/implementation address) in the init_code
3. Update `init_code` in the generator program
4. Run the generator to find a salt that produces your desired address pattern

**Example:**
```python
# In generate_address.py or src/main.rs, set:
init_code = compiled_bytecode + encoded_constructor_args
```

