#!/usr/bin/env python3
"""
Generate ECDSA key pair, derive Ethereum address, and compute CREATE2 contract address.
"""

from eth_keys import keys
from eth_utils import keccak, to_checksum_address, to_hex
from Crypto.Hash import keccak as pycryptodome_keccak
import secrets
import os


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
    """Load keys from myaddress.dat file."""
    with open("myaddress.dat", "r") as f:
        lines = f.readlines()
        if len(lines) < 2:
            raise ValueError("myaddress.dat must contain two lines (private key and public key)")
        
        # Parse private key (remove 0x prefix if present)
        private_key_hex = lines[0].strip().lstrip("0x")
        private_key_bytes = bytes.fromhex(private_key_hex)
        
        if len(private_key_bytes) != 32:
            raise ValueError("Private key must be 32 bytes")
        
        private_key = keys.PrivateKey(private_key_bytes)
        
        # Parse public key (remove 0x prefix if present)
        public_key_hex = lines[1].strip().lstrip("0x")
        public_key_bytes = bytes.fromhex(public_key_hex)
        public_key = keys.PublicKey(public_key_bytes)
        
        # Verify that the private key derives the public key
        derived_public_key = private_key.public_key
        if derived_public_key.to_bytes() != public_key.to_bytes():
            raise ValueError("Private key does not match public key")
        
        return private_key, public_key


def save_keys_to_file(private_key, public_key, first_contract_address=None):
    """Save keys to myaddress.dat file."""
    with open("myaddress.dat", "w") as f:
        f.write(f"{to_hex(private_key.to_bytes())}\n")
        f.write(f"{to_hex(public_key.to_bytes())}\n")
        if first_contract_address is not None:
            f.write(f"firstContractAddress={to_hex(first_contract_address)}\n")


def load_or_generate_keys():
    """Load keys from myaddress.dat or generate new ones."""
    if os.path.exists("myaddress.dat"):
        try:
            private_key, public_key = load_keys_from_file()
            print("Loaded keys from myaddress.dat")
            return private_key, public_key, False
        except Exception as e:
            print(f"myaddress.dat exists but is invalid: {e}")
            print("Generating new key pair...")
            private_key, public_key = generate_keypair()
            try:
                save_keys_to_file(private_key, public_key, None)
                print("Saved keys to myaddress.dat")
            except Exception as e:
                print(f"Warning: Failed to save keys to myaddress.dat: {e}")
            return private_key, public_key, True
    else:
        print("myaddress.dat not found")
        print("Generating new key pair...")
        private_key, public_key = generate_keypair()
        try:
            save_keys_to_file(private_key, public_key, None)
            print("Saved keys to myaddress.dat")
        except Exception as e:
            print(f"Warning: Failed to save keys to myaddress.dat: {e}")
        return private_key, public_key, True


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
    print("=" * 70)
    print("ECDSA Key Generation and CREATE2 Address Search")
    print("=" * 70)
    print()
    
    # Step 1: Load or generate private key and public key
    print("Step 1: Loading or generating ECDSA key pair...")
    private_key, public_key, is_new = load_or_generate_keys()
    
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
    
    # Step 3: Search for CREATE2 address with most trailing zeros
    print("Step 3: Searching for CREATE2 address with most trailing zeros...")
    print("Note: CREATE2 requires the contract's initialization code (bytecode + constructor args).")
    print("For demonstration, using empty init code. Replace with actual contract bytecode.")
    print()
    
    # Example: Using empty init code (user should replace with actual contract bytecode)
    init_code = b''  # Replace with actual contract initialization code
    
    # Compute first CREATE2 address (salt = 0, which is 32 bytes of zeros)
    first_salt = bytes(32)  # 32 bytes of zeros
    first_contract_address = compute_create2_address(deployer_address, first_salt, init_code)
    first_contract_address_hex = to_checksum_address(to_hex(first_contract_address))
    print(f"First CREATE2 Address (salt=0): {first_contract_address_hex}")
    
    # Save the first contract address to myaddress.dat
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
            contract_address = compute_create2_address(deployer_address, bytes(salt), init_code)
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

