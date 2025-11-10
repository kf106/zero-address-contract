# Zero Address Contract - CREATE2 Address Generator

This program generates an ECDSA private key, derives the public key and Ethereum address, then computes the CREATE2 contract address for a contract deployed with salt 0.

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
```bash
pip install -r requirements.txt
python generate_address.py
```

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

