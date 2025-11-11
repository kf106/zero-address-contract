#!/usr/bin/env python3
"""
Generate ECDSA key pair, derive Ethereum address, and compute CREATE2 contract address.
"""

from eth_keys import keys
from eth_utils import keccak, to_checksum_address, to_hex
from Crypto.Hash import keccak as pycryptodome_keccak
import secrets
import os
import argparse
import time
import rlp


def keccak256(data: bytes) -> bytes:
    """Compute Keccak-256 hash."""
    return keccak(data)


def generate_keypair():
    """Generate a new ECDSA private key and derive the public key."""
    # Generate a random 32-byte private key
    private_key_bytes = secrets.token_bytes(32)
    private_key = keys.PrivateKey(private_key_bytes)
    
    # Derive public key
    public_key = private_key.public_key
    
    return private_key, public_key


def derive_ethereum_address(public_key):
    """Derive Ethereum address from public key."""
    # Ethereum address is the last 20 bytes of Keccak-256 hash of the public key
    public_key_bytes = public_key.to_bytes()
    # Remove the 0x04 prefix if present (uncompressed public key format)
    if public_key_bytes[0] == 0x04:
        public_key_bytes = public_key_bytes[1:]
    
    hash_bytes = keccak256(public_key_bytes)
    address_bytes = hash_bytes[-20:]  # Last 20 bytes
    
    return address_bytes


def load_keys_from_file():
    """Load keys and firstContractAddress from myaddress.dat file."""
    with open("myaddress.dat", "r") as f:
        lines = f.readlines()
        if len(lines) < 2:
            raise ValueError("myaddress.dat must contain at least two lines (private key and public key)")
        
        # Parse private key (remove 0x prefix if present)
        private_key_hex = lines[0].strip().lstrip("0x")
        private_key_bytes = bytes.fromhex(private_key_hex)
        
        if len(private_key_bytes) != 32:
            raise ValueError("Private key must be 32 bytes")
        
        private_key = keys.PrivateKey(private_key_bytes)
        
        # Parse public key (remove 0x prefix if present)
        public_key_hex = lines[1].strip().lstrip("0x")
        # Handle odd-length hex strings (pad with leading zero if needed)
        if len(public_key_hex) % 2 == 1:
            public_key_hex = "0" + public_key_hex
        public_key_bytes = bytes.fromhex(public_key_hex)
        # Handle both formats: 64 bytes (no prefix) or 65 bytes (with 0x04 prefix)
        if len(public_key_bytes) == 65 and public_key_bytes[0] == 0x04:
            # Remove 0x04 prefix for eth_keys (it expects 64 bytes)
            public_key_bytes = public_key_bytes[1:]
        elif len(public_key_bytes) != 64:
            raise ValueError(f"Public key must be 64 or 65 bytes, got {len(public_key_bytes)}")
        public_key = keys.PublicKey(public_key_bytes)
        
        # Verify that the private key derives the public key
        derived_public_key = private_key.public_key
        if derived_public_key.to_bytes() != public_key.to_bytes():
            raise ValueError("Private key does not match public key")
        
        # Parse firstContractAddress if present (optional third line)
        first_contract_address = None
        if len(lines) >= 3:
            third_line = lines[2].strip()
            if third_line.startswith("firstContractAddress="):
                addr_hex = third_line.split("=", 1)[1].lstrip("0x")
                first_contract_address = bytes.fromhex(addr_hex)
                if len(first_contract_address) != 20:
                    raise ValueError(f"firstContractAddress must be 20 bytes, got {len(first_contract_address)}")
        
        return private_key, public_key, first_contract_address


def save_keys_to_file(private_key, public_key, first_contract_address=None):
    """Save keys to myaddress.dat file."""
    with open("myaddress.dat", "w") as f:
        f.write(f"{to_hex(private_key.to_bytes())}\n")
        # Save public key in uncompressed format (65 bytes with 0x04 prefix)
        # eth_keys returns 64 bytes, so we prepend 0x04 to match Rust format
        public_key_bytes = public_key.to_bytes()
        if len(public_key_bytes) == 64:
            # Prepend 0x04 for uncompressed format
            public_key_bytes = b'\x04' + public_key_bytes
        f.write(f"{to_hex(public_key_bytes)}\n")
        if first_contract_address is not None:
            f.write(f"firstContractAddress={to_hex(first_contract_address)}\n")


def load_or_generate_keys():
    """Load keys from myaddress.dat or generate new ones."""
    if os.path.exists("myaddress.dat"):
        try:
            private_key, public_key, first_contract_address = load_keys_from_file()
            print("Loaded keys from myaddress.dat")
            if first_contract_address is not None:
                print(f"Loaded firstContractAddress from myaddress.dat")
            return private_key, public_key, False, first_contract_address
        except Exception as e:
            print(f"myaddress.dat exists but is invalid: {e}")
            print("Generating new key pair...")
            private_key, public_key = generate_keypair()
            try:
                save_keys_to_file(private_key, public_key, None)
                print("Saved keys to myaddress.dat")
            except Exception as e:
                print(f"Warning: Failed to save keys to myaddress.dat: {e}")
            return private_key, public_key, True, None
    else:
        print("myaddress.dat not found")
        print("Generating new key pair...")
        private_key, public_key = generate_keypair()
        try:
            save_keys_to_file(private_key, public_key, None)
            print("Saved keys to myaddress.dat")
        except Exception as e:
            print(f"Warning: Failed to save keys to myaddress.dat: {e}")
        return private_key, public_key, True, None


def calculate_zero_address_time(deployer_address: bytes, init_code: bytes, sample_size: int = 100000) -> float:
    """
    Calculate expected time to find zero address (all 20 bytes are zero).
    Returns time in millennia.
    """
    # Benchmark computation speed
    salt = bytearray(32)
    start_time = time.time()
    
    for _ in range(sample_size):
        compute_create2_address(deployer_address, bytes(salt), init_code)
        # Increment salt for next iteration
        for i in range(31, -1, -1):
            salt[i] = (salt[i] + 1) % 256
            if salt[i] != 0:
                break
    
    elapsed_time = time.time() - start_time
    addresses_per_second = sample_size / elapsed_time
    
    # Probability of zero address: 1 / (256^20) = 1 / (2^160)
    # Expected number of attempts: 2^160
    # 2^160 is approximately 1.4615016373309029e+48
    expected_attempts = 2.0 ** 160
    time_seconds = expected_attempts / addresses_per_second
    
    # Convert to millennia (1 millennium = 1000 years)
    seconds_per_millennium = 1000.0 * 365.25 * 24.0 * 3600.0  # ~3.15576e10
    time_millennia = time_seconds / seconds_per_millennium
    
    print(f"Benchmark: {int(addresses_per_second):,} addresses/second")
    print(f"Expected attempts to find zero address: 2^160 ≈ {expected_attempts:.2e}")
    
    return time_millennia


def count_trailing_zeros(address: bytes) -> int:
    """Count trailing zeros in an address (from the rightmost byte)."""
    count = 0
    for byte in reversed(address):
        if byte == 0:
            count += 1
        else:
            break
    return count


def increment_salt(salt_bytes: bytearray) -> None:
    """Increment a 32-byte big-endian salt in place."""
    for i in range(31, -1, -1):
        if salt_bytes[i] == 0xFF:
            salt_bytes[i] = 0x00
        else:
            salt_bytes[i] += 1
            break


def compute_create_address(deployer_address: bytes, nonce: int) -> bytes:
    """
    Compute CREATE contract address (for deploying CREATE2Deployer from EOA).
    
    Formula: keccak256(rlp([deployer_address, nonce]))[12:]
    
    Args:
        deployer_address: 20-byte deployer address (EOA)
        nonce: Transaction nonce (0 for first deployment)
    
    Returns:
        20-byte contract address
    """
    # RLP encode [deployer_address, nonce]
    rlp_encoded = rlp.encode([deployer_address, nonce])
    
    # Compute Keccak-256 hash
    create_hash = keccak256(rlp_encoded)
    
    # Take last 20 bytes (address)
    contract_address = create_hash[-20:]
    
    return contract_address


def compute_create2_address(deployer_address: bytes, salt: bytes, init_code: bytes) -> bytes:
    """
    Compute CREATE2 contract address.
    
    Formula: keccak256(0xff ++ deployer_address ++ salt ++ keccak256(init_code))[12:]
    
    Args:
        deployer_address: 20-byte deployer address
        salt: 32-byte salt (as integer, will be converted to 32 bytes)
        init_code: Contract initialization code (bytecode + constructor args)
    
    Returns:
        20-byte contract address
    """
    # Compute hash of init code
    init_code_hash = keccak256(init_code)
    
    # Concatenate: 0xff (1 byte) + deployer_address (20 bytes) + salt (32 bytes) + init_code_hash (32 bytes)
    create2_input = b'\xff' + deployer_address + salt + init_code_hash
    
    # Compute Keccak-256 hash
    create2_hash = keccak256(create2_input)
    
    # Take last 20 bytes (address)
    contract_address = create2_hash[-20:]
    
    return contract_address


def main():
    parser = argparse.ArgumentParser(
        description="Generate ECDSA keys and search for CREATE2 addresses with trailing zeros"
    )
    parser.add_argument(
        '-t', '--time-estimate',
        action='store_true',
        help='Calculate and report expected time in millennia to find zero address'
    )
    args = parser.parse_args()
    
    print("=" * 70)
    print("ECDSA Key Generation and CREATE2 Address Search")
    print("=" * 70)
    print()
    
    # Step 1: Load or generate private key and public key
    print("Step 1: Loading or generating ECDSA key pair...")
    private_key, public_key, is_new, loaded_first_contract_address = load_or_generate_keys()
    
    if is_new:
        print("Generated new key pair")
    else:
        print("Using existing key pair from myaddress.dat")
    print(f"Private Key (hex): {to_hex(private_key.to_bytes())}")
    print(f"Public Key (hex):  {to_hex(public_key.to_bytes())}")
    print()
    
    # Step 2: Derive Ethereum address
    print("Step 2: Deriving Ethereum address from public key...")
    deployer_address = derive_ethereum_address(public_key)
    deployer_address_hex = to_checksum_address(to_hex(deployer_address))
    print(f"Deployer Address: {deployer_address_hex}")
    print()
    
    # SimpleProxy contract init code (bytecode + constructor args)
    # Constructor arg: address(0) which defaults to 0x2c36dd7Bb3E95E7a0219E70737eE8041f22d2081
    # Read from init_code.txt (generated by get_init_code.js from compiled contract)
    try:
        with open("init_code.txt", "r") as f:
            init_code_hex = f.read().strip()
        init_code = bytes.fromhex(init_code_hex)
    except FileNotFoundError:
        print("Error: init_code.txt not found. Please run 'npm run compile' and 'node get_init_code.js' first.")
        return
    except Exception as e:
        print(f"Error reading init_code.txt: {e}")
        return
    
    # If -t flag is set, calculate and report time estimate
    if args.time_estimate:
        print("=" * 70)
        print("Time Estimate for Zero Address (all 20 bytes = 0x00)")
        print("=" * 70)
        print()
        print("Benchmarking computation speed...")
        # For time estimate, we need factory address first
        create2deployer_bytecode_hex = (
            "608060405234801561001057600080fd5b50610245806100206000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c80633e4b9f7a1461003b5780634af63f021461006a575b600080fd5b61004e61004936600461015a565b61007d565b6040516001600160a01b03909116815260200160405180910390f35b61004e61007836600461015a565b6100dc565b8151602080840191909120604080516001600160f81b0319818501523060601b6bffffffffffffffffffffffff191660218201526035810185905260558082019390935281518082039093018352607501905280519101205b92915050565b6000818351602085016000f590506001600160a01b0381166100d65760405162461bcd60e51b815260206004820152601960248201527f43524541544532206465706c6f796d656e74206661696c656400000000000000604482015260640160405180910390fd5b634e487b7160e01b600052604160045260246000fd5b6000806040838503121561016d57600080fd5b823567ffffffffffffffff8082111561018557600080fd5b818501915085601f83011261019957600080fd5b8135818111156101ab576101ab610144565b604051601f8201601f19908116603f011681019083821181831017156101d3576101d3610144565b816040528281528860208487010111156101ec57600080fd5b82602086016020830137600060209382018401529896909101359650505050505056fea26469706673582212208855269245d440fa8c30bdc8f8e1a3efb73d586080803c7785d34eaf83a7b21764736f6c63430008140033"
        )
        factory_address = compute_create_address(deployer_address, 0)
        time_millennia = calculate_zero_address_time(factory_address, init_code, 100000)
        print()
        print(f"Expected time to find zero address: {time_millennia:.2e} millennia")
        print(f"(This is approximately {time_millennia / 13.8:.2e} times the age of the universe)")
        print()
        return
    
    # Step 3: Compute CREATE2Deployer factory address (deployed from EOA using CREATE, nonce 0)
    print("Step 3: Computing CREATE2Deployer factory address...")
    # CREATE2Deployer bytecode (no constructor args)
    create2deployer_bytecode_hex = (
        "608060405234801561001057600080fd5b50610245806100206000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c80633e4b9f7a1461003b5780634af63f021461006a575b600080fd5b61004e61004936600461015a565b61007d565b6040516001600160a01b03909116815260200160405180910390f35b61004e61007836600461015a565b6100dc565b8151602080840191909120604080516001600160f81b0319818501523060601b6bffffffffffffffffffffffff191660218201526035810185905260558082019390935281518082039093018352607501905280519101205b92915050565b6000818351602085016000f590506001600160a01b0381166100d65760405162461bcd60e51b815260206004820152601960248201527f43524541544532206465706c6f796d656e74206661696c656400000000000000604482015260640160405180910390fd5b634e487b7160e01b600052604160045260246000fd5b6000806040838503121561016d57600080fd5b823567ffffffffffffffff8082111561018557600080fd5b818501915085601f83011261019957600080fd5b8135818111156101ab576101ab610144565b604051601f8201601f19908116603f011681019083821181831017156101d3576101d3610144565b816040528281528860208487010111156101ec57600080fd5b82602086016020830137600060209382018401529896909101359650505050505056fea26469706673582212208855269245d440fa8c30bdc8f8e1a3efb73d586080803c7785d34eaf83a7b21764736f6c63430008140033"
    )
    create2deployer_bytecode = bytes.fromhex(create2deployer_bytecode_hex)
    
    # Compute where CREATE2Deployer would be deployed from EOA (CREATE, nonce 0)
    factory_address = compute_create_address(deployer_address, 0)
    factory_address_hex = to_checksum_address(to_hex(factory_address))
    print(f"CREATE2Deployer factory address (from EOA, nonce 0): {factory_address_hex}")
    print()
    
    # Step 4: Search for CREATE2 address with most trailing zeros
    print("Step 4: Searching for CREATE2 address with most trailing zeros...")
    print(f"Using SimpleProxy contract init code ({len(init_code)} bytes)")
    print("Constructor arg: address(0) -> defaults to 0x2c36dd7Bb3E95E7a0219E70737eE8041f22d2081")
    print(f"Using factory address as deployer in CREATE2: {factory_address_hex}")
    print()
    
    # Compute first CREATE2 address (salt = 0, which is 32 bytes of zeros)
    # Use factory_address, not deployer_address (EOA)
    first_salt = bytes(32)  # 32 bytes of zeros
    first_contract_address = compute_create2_address(factory_address, first_salt, init_code)
    first_contract_address_hex = to_checksum_address(to_hex(first_contract_address))
    print(f"First CREATE2 Address (salt=0): {first_contract_address_hex}")
    
    # Verify or save the first contract address
    if loaded_first_contract_address is not None:
        # Verify that the computed address matches the loaded one
        if first_contract_address != loaded_first_contract_address:
            print(f"ERROR: Computed firstContractAddress ({first_contract_address_hex}) does not match")
            print(f"       the one in myaddress.dat ({to_checksum_address(to_hex(loaded_first_contract_address))})")
            return
        print("Verified: Computed firstContractAddress matches the one in myaddress.dat")
    elif is_new:
        # Only save when generating new keys
        try:
            save_keys_to_file(private_key, public_key, first_contract_address)
            print("Saved firstContractAddress to myaddress.dat")
        except Exception as e:
            print(f"Warning: Failed to save firstContractAddress to myaddress.dat: {e}")
    print()
    
    salt = bytearray(32)  # Start at 0x00...00
    best_salt = bytes(salt)
    best_address = first_contract_address
    best_trailing_zeros = count_trailing_zeros(best_address)
    checked = 0
    
    print("Searching through salt values...")
    print(f"Current best: {best_trailing_zeros} trailing zeros at salt 0x{best_salt.hex()}")
    
    # Search through salt values
    try:
        while True:
            contract_address = compute_create2_address(factory_address, bytes(salt), init_code)
            trailing_zeros = count_trailing_zeros(contract_address)
            
            if trailing_zeros > best_trailing_zeros:
                best_trailing_zeros = trailing_zeros
                best_salt = bytes(salt)
                best_address = contract_address
                best_address_hex = to_checksum_address(to_hex(best_address))
                print(f"New best: {best_trailing_zeros} trailing zeros at salt 0x{best_salt.hex()} -> {best_address_hex}")
            
            checked += 1
            if checked % 100000 == 0:
                print(f"Checked {checked:,} salts... (best: {best_trailing_zeros} zeros)", end='\r')
            
            increment_salt(salt)
            
            # Stop if we find an address with 20 trailing zeros (all zeros, very unlikely)
            if best_trailing_zeros >= 20:
                break
            
            # Optional: Add a limit to prevent infinite loops
            # Uncomment the following lines to set a maximum search limit
            # if salt >= 1_000_000:
            #     break
    except KeyboardInterrupt:
        print("\n\nSearch interrupted by user.")
    
    print()
    print()
    
    best_address_hex = to_checksum_address(to_hex(best_address))
    
    print("=" * 70)
    print("Results:")
    print("=" * 70)
    print(f"Private Key:      {to_hex(private_key.to_bytes())}")
    print(f"Deployer Address: {deployer_address_hex}")
    print(f"Best Salt:        0x{best_salt.hex()}")
    print(f"Trailing Zeros:   {best_trailing_zeros} bytes")
    print(f"CREATE2 Address:  {best_address_hex}")
    print(f"Address (hex):    {to_hex(best_address)}")
    print()
    print(f"Searched through {checked:,} salt values")


if __name__ == "__main__":
    main()

