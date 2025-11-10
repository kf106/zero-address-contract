use secp256k1::{Secp256k1, SecretKey, PublicKey};
use sha3::{Keccak256, Digest};
use rand::rngs::OsRng;
use hex;
use std::fs;
use std::io::{self, Write};

/// Compute Keccak-256 hash
fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Generate ECDSA key pair
fn generate_keypair() -> (SecretKey, PublicKey) {
    let secp = Secp256k1::new();
    let mut rng = OsRng;
    let secret_key = SecretKey::new(&mut rng);
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    (secret_key, public_key)
}

/// Derive Ethereum address from public key
/// Ethereum address is the last 20 bytes of Keccak-256 hash of the public key
fn derive_ethereum_address(public_key: &PublicKey) -> [u8; 20] {
    // Get uncompressed public key (65 bytes: 0x04 + 64 bytes)
    let public_key_bytes = public_key.serialize_uncompressed();
    // Remove the 0x04 prefix (first byte)
    let public_key_no_prefix = &public_key_bytes[1..];
    
    // Hash with Keccak-256
    let hash = keccak256(public_key_no_prefix);
    
    // Take last 20 bytes
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    address
}

/// Compute CREATE2 contract address
/// Formula: keccak256(0xff ++ deployer_address ++ salt ++ keccak256(init_code))[12:]
fn compute_create2_address(
    deployer_address: &[u8; 20],
    salt: &[u8; 32],
    init_code: &[u8],
) -> [u8; 20] {
    // Compute hash of init code
    let init_code_hash = keccak256(init_code);
    
    // Concatenate: 0xff (1 byte) + deployer_address (20 bytes) + salt (32 bytes) + init_code_hash (32 bytes)
    let mut create2_input = Vec::with_capacity(1 + 20 + 32 + 32);
    create2_input.push(0xff);
    create2_input.extend_from_slice(deployer_address);
    create2_input.extend_from_slice(salt);
    create2_input.extend_from_slice(&init_code_hash);
    
    // Compute Keccak-256 hash
    let create2_hash = keccak256(&create2_input);
    
    // Take last 20 bytes (address)
    let mut contract_address = [0u8; 20];
    contract_address.copy_from_slice(&create2_hash[12..]);
    contract_address
}

/// Increment a 32-byte big-endian salt in place
fn increment_salt(salt: &mut [u8; 32]) {
    for byte in salt.iter_mut().rev() {
        if *byte == u8::MAX {
            *byte = 0;
        } else {
            *byte += 1;
            break;
        }
    }
}

/// Count trailing zeros in an address (from the rightmost byte)
fn count_trailing_zeros(address: &[u8; 20]) -> usize {
    let mut count = 0;
    for byte in address.iter().rev() {
        if *byte == 0 {
            count += 1;
        } else {
            break;
        }
    }
    count
}

/// Load keys from myaddress.dat file
fn load_keys_from_file() -> Result<(SecretKey, PublicKey), String> {
    let contents = fs::read_to_string("myaddress.dat")
        .map_err(|e| format!("Failed to read myaddress.dat: {}", e))?;
    
    let lines: Vec<&str> = contents.lines().collect();
    if lines.len() < 2 {
        return Err("myaddress.dat must contain at least two lines (private key and public key)".to_string());
    }
    
    // Parse private key (remove 0x prefix if present)
    let private_key_hex = lines[0].trim().trim_start_matches("0x");
    let private_key_bytes = hex::decode(private_key_hex)
        .map_err(|e| format!("Failed to decode private key: {}", e))?;
    
    if private_key_bytes.len() != 32 {
        return Err("Private key must be 32 bytes".to_string());
    }
    
    let secret_key = SecretKey::from_slice(&private_key_bytes)
        .map_err(|e| format!("Invalid private key: {}", e))?;
    
    // Parse public key (remove 0x prefix if present)
    let public_key_hex = lines[1].trim().trim_start_matches("0x");
    let public_key_bytes = hex::decode(public_key_hex)
        .map_err(|e| format!("Failed to decode public key: {}", e))?;
    
    let public_key = PublicKey::from_slice(&public_key_bytes)
        .map_err(|e| format!("Invalid public key: {}", e))?;
    
    // Verify that the private key derives the public key
    let secp = Secp256k1::new();
    let derived_public_key = PublicKey::from_secret_key(&secp, &secret_key);
    
    if derived_public_key != public_key {
        return Err("Private key does not match public key".to_string());
    }
    
    Ok((secret_key, public_key))
}

/// Save keys to myaddress.dat file
fn save_keys_to_file(secret_key: &SecretKey, public_key: &PublicKey, first_contract_address: Option<&[u8; 20]>) -> Result<(), String> {
    let secret_key_bytes = secret_key.secret_bytes();
    let public_key_bytes = public_key.serialize_uncompressed();
    
    let mut contents = format!("0x{}\n0x{}\n", 
                              hex::encode(secret_key_bytes),
                              hex::encode(public_key_bytes));
    
    // Add firstContractAddress if provided
    if let Some(addr) = first_contract_address {
        contents.push_str(&format!("firstContractAddress=0x{}\n", hex::encode(addr)));
    }
    
    fs::write("myaddress.dat", contents)
        .map_err(|e| format!("Failed to write myaddress.dat: {}", e))?;
    
    Ok(())
}

/// Load or generate key pair
fn load_or_generate_keys() -> (SecretKey, PublicKey, bool) {
    match load_keys_from_file() {
        Ok((secret_key, public_key)) => {
            println!("Loaded keys from myaddress.dat");
            (secret_key, public_key, false)
        }
        Err(e) => {
            println!("myaddress.dat not found or invalid: {}", e);
            println!("Generating new key pair...");
            let (secret_key, public_key) = generate_keypair();
            match save_keys_to_file(&secret_key, &public_key, None) {
                Ok(()) => {
                    println!("Saved keys to myaddress.dat");
                    (secret_key, public_key, true)
                }
                Err(e) => {
                    eprintln!("Warning: Failed to save keys to myaddress.dat: {}", e);
                    (secret_key, public_key, true)
                }
            }
        }
    }
}

/// Convert address to checksummed format (EIP-55)
fn to_checksum_address(address: &[u8; 20]) -> String {
    let address_hex = hex::encode(address);
    // Hash the lowercase hex string (without 0x prefix) as ASCII bytes
    let hash = keccak256(address_hex.as_bytes());
    let hash_hex = hex::encode(hash);
    
    address_hex
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if c.is_ascii_alphabetic() {
                let hash_char = hash_hex.chars().nth(i).unwrap();
                if hash_char.to_digit(16).unwrap() >= 8 {
                    c.to_uppercase().next().unwrap()
                } else {
                    c.to_lowercase().next().unwrap()
                }
            } else {
                c
            }
        })
        .collect::<String>()
}

fn main() {
    println!("{}", "=".repeat(70));
    println!("ECDSA Key Generation and CREATE2 Address Search");
    println!("{}", "=".repeat(70));
    println!();
    
    // Step 1: Load or generate private key and public key
    println!("Step 1: Loading or generating ECDSA key pair...");
    let (secret_key, public_key, is_new) = load_or_generate_keys();
    
    let secret_key_bytes = secret_key.secret_bytes();
    let public_key_bytes = public_key.serialize_uncompressed();
    
    if is_new {
        println!("Generated new key pair");
    } else {
        println!("Using existing key pair from myaddress.dat");
    }
    println!("Private Key (hex): 0x{}", hex::encode(secret_key_bytes));
    println!("Public Key (hex):  0x{}", hex::encode(public_key_bytes));
    println!();
    
    // Step 2: Derive Ethereum address
    println!("Step 2: Deriving Ethereum address from public key...");
    let deployer_address = derive_ethereum_address(&public_key);
    let deployer_address_hex = to_checksum_address(&deployer_address);
    println!("Deployer Address: 0x{}", deployer_address_hex);
    println!();
    
    // Step 3: Search for CREATE2 address with most trailing zeros
    println!("Step 3: Searching for CREATE2 address with most trailing zeros...");
    println!("Note: CREATE2 requires the contract's initialization code (bytecode + constructor args).");
    println!("For demonstration, using empty init code. Replace with actual contract bytecode.");
    println!();
    
    let init_code = b""; // Replace with actual contract initialization code
    
    // Compute first CREATE2 address (salt = 0, which is 32 bytes of zeros)
    let first_salt = [0u8; 32];
    let first_contract_address = compute_create2_address(&deployer_address, &first_salt, init_code);
    let first_contract_address_hex = to_checksum_address(&first_contract_address);
    println!("First CREATE2 Address (salt=0): 0x{}", first_contract_address_hex);
    
    // Save the first contract address to myaddress.dat
    match save_keys_to_file(&secret_key, &public_key, Some(&first_contract_address)) {
        Ok(()) => {
            println!("Saved firstContractAddress to myaddress.dat");
        }
        Err(e) => {
            eprintln!("Warning: Failed to save firstContractAddress to myaddress.dat: {}", e);
        }
    }
    println!();
    
    let mut salt = [0u8; 32];
    let mut best_salt = salt;
    let mut best_address = first_contract_address;
    let mut best_trailing_zeros = count_trailing_zeros(&best_address);
    let mut checked = 0u64;
    
    println!("Searching through salt values...");
    println!(
        "Current best: {} trailing zeros at salt 0x{}",
        best_trailing_zeros,
        hex::encode(best_salt)
    );
    
    // Search through salt values
    loop {
        let contract_address = compute_create2_address(&deployer_address, &salt, init_code);
        let trailing_zeros = count_trailing_zeros(&contract_address);
        
        if trailing_zeros > best_trailing_zeros {
            best_trailing_zeros = trailing_zeros;
            best_salt = salt;
            best_address = contract_address;
            let best_address_hex = to_checksum_address(&best_address);
            println!(
                "New best: {} trailing zeros at salt 0x{} -> 0x{}",
                best_trailing_zeros,
                hex::encode(best_salt),
                best_address_hex
            );
        }
        
        checked += 1;
        if checked % 100000 == 0 {
            print!("Checked {} salts... (best: {} zeros)\r", checked, best_trailing_zeros);
            io::stdout().flush().unwrap();
        }
        
        increment_salt(&mut salt);
        
        // Stop if we find an address with 20 trailing zeros (all zeros, very unlikely)
        if best_trailing_zeros >= 20 {
            break;
        }
        
        // Optional: Add a limit to prevent infinite loops
        // Uncomment the following lines to set a maximum search limit
        // if salt >= 1_000_000 {
        //     break;
        // }
    }
    
    println!();
    println!();
    
    let best_address_hex = to_checksum_address(&best_address);
    
    println!("{}", "=".repeat(70));
    println!("Results:");
    println!("{}", "=".repeat(70));
    println!("Private Key:      0x{}", hex::encode(secret_key_bytes));
    println!("Deployer Address: 0x{}", deployer_address_hex);
    println!("Best Salt:        0x{}", hex::encode(best_salt));
    println!("Trailing Zeros:   {} bytes", best_trailing_zeros);
    println!("CREATE2 Address:  0x{}", best_address_hex);
    println!("Address (hex):    0x{}", hex::encode(best_address));
    println!();
    println!("Searched through {} salt values", checked);
}

