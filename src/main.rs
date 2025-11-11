use secp256k1::{Secp256k1, SecretKey, PublicKey};
use sha3::{Keccak256, Digest};
use rand::rngs::OsRng;
use hex;
use std::fs;
use std::io::{self, Write};
use std::time::Instant;
use clap::Parser;
use rlp::RlpStream;

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

/// Compute CREATE contract address (for deploying CREATE2Deployer from EOA)
/// Formula: keccak256(rlp([deployer_address, nonce]))[12:]
fn compute_create_address(deployer_address: &[u8; 20], nonce: u64) -> [u8; 20] {
    // RLP encode [deployer_address, nonce]
    let mut stream = RlpStream::new();
    stream.begin_list(2);
    stream.append(&deployer_address.as_slice());
    stream.append(&nonce);
    let rlp_encoded = stream.out();
    
    // Compute Keccak-256 hash
    let create_hash = keccak256(&rlp_encoded);
    
    // Take last 20 bytes (address)
    let mut contract_address = [0u8; 20];
    contract_address.copy_from_slice(&create_hash[12..]);
    contract_address
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

fn count_leading_zeros(address: &[u8; 20]) -> usize {
    let mut count = 0;
    for byte in address {
        if *byte == 0 {
            count += 1;
        } else {
            break;
        }
    }
    count
}

/// Load keys and firstContractAddress from myaddress.dat file
fn load_keys_from_file() -> Result<(SecretKey, PublicKey, Option<[u8; 20]>), String> {
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
    let mut public_key_bytes = hex::decode(public_key_hex)
        .map_err(|e| format!("Failed to decode public key: {}", e))?;
    
    // Handle both formats: 64 bytes (no prefix) or 65 bytes (with 0x04 prefix)
    // Rust expects 65 bytes with 0x04 prefix for uncompressed format
    if public_key_bytes.len() == 64 {
        // Prepend 0x04 for uncompressed format
        let mut full_key = vec![0x04];
        full_key.extend_from_slice(&public_key_bytes);
        public_key_bytes = full_key;
    } else if public_key_bytes.len() != 65 {
        return Err(format!("Public key must be 64 or 65 bytes, got {}", public_key_bytes.len()));
    }
    
    let public_key = PublicKey::from_slice(&public_key_bytes)
        .map_err(|e| format!("Invalid public key: {}", e))?;
    
    // Verify that the private key derives the public key
    let secp = Secp256k1::new();
    let derived_public_key = PublicKey::from_secret_key(&secp, &secret_key);
    
    if derived_public_key != public_key {
        return Err("Private key does not match public key".to_string());
    }
    
    // Parse firstContractAddress if present (optional third line)
    let first_contract_address = if lines.len() >= 3 {
        let third_line = lines[2].trim();
        if third_line.starts_with("firstContractAddress=") {
            let addr_hex = third_line.split('=').nth(1)
                .ok_or("Invalid firstContractAddress format")?
                .trim()
                .trim_start_matches("0x");
            let addr_bytes = hex::decode(addr_hex)
                .map_err(|e| format!("Failed to decode firstContractAddress: {}", e))?;
            if addr_bytes.len() != 20 {
                return Err(format!("firstContractAddress must be 20 bytes, got {}", addr_bytes.len()));
            }
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&addr_bytes);
            Some(addr)
        } else {
            None
        }
    } else {
        None
    };
    
    Ok((secret_key, public_key, first_contract_address))
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
fn load_or_generate_keys() -> (SecretKey, PublicKey, bool, Option<[u8; 20]>) {
    match load_keys_from_file() {
        Ok((secret_key, public_key, first_contract_address)) => {
            println!("Loaded keys from myaddress.dat");
            if first_contract_address.is_some() {
                println!("Loaded firstContractAddress from myaddress.dat");
            }
            (secret_key, public_key, false, first_contract_address)
        }
        Err(e) => {
            println!("myaddress.dat not found or invalid: {}", e);
            println!("Generating new key pair...");
            let (secret_key, public_key) = generate_keypair();
            match save_keys_to_file(&secret_key, &public_key, None) {
                Ok(()) => {
                    println!("Saved keys to myaddress.dat");
                    (secret_key, public_key, true, None)
                }
                Err(e) => {
                    eprintln!("Warning: Failed to save keys to myaddress.dat: {}", e);
                    (secret_key, public_key, true, None)
                }
            }
        }
    }
}

/// Calculate expected time to find zero address (all 20 bytes are zero)
/// Returns time in millennia
fn calculate_zero_address_time(
    deployer_address: &[u8; 20],
    init_code: &[u8],
    sample_size: usize,
) -> f64 {
    // Benchmark computation speed
    let start = Instant::now();
    let mut salt = [0u8; 32];
    
    for _ in 0..sample_size {
        compute_create2_address(deployer_address, &salt, init_code);
        // Increment salt for next iteration
        for i in (0..32).rev() {
            salt[i] = salt[i].wrapping_add(1);
            if salt[i] != 0 {
                break;
            }
        }
    }
    
    let elapsed = start.elapsed();
    let addresses_per_second = sample_size as f64 / elapsed.as_secs_f64();
    
    // Probability of zero address: 1 / (256^20) = 1 / (2^160)
    // Expected number of attempts: 2^160
    // Using logarithms to avoid overflow: log2(2^160) = 160
    // Expected attempts = 2^160
    // Time in seconds = 2^160 / addresses_per_second
    
    // Calculate 2^160 using logarithms to avoid overflow
    // log10(2^160) = 160 * log10(2) ≈ 160 * 0.30103 ≈ 48.1648
    // 2^160 ≈ 10^48.1648 ≈ 1.4615 × 10^48
    
    // For very large numbers, we'll use a more direct approach
    // Expected attempts = 2^160
    // We'll calculate this using f64 with appropriate scaling
    
    // 2^160 is approximately 1.4615016373309029e+48
    let expected_attempts = 2_f64.powi(160);
    let time_seconds = expected_attempts / addresses_per_second;
    
    // Convert to millennia (1 millennium = 1000 years = 3.1536e10 seconds)
    let seconds_per_millennium = 1000.0 * 365.25 * 24.0 * 3600.0; // ~3.15576e10
    let time_millennia = time_seconds / seconds_per_millennium;
    
    println!("Benchmark: {} addresses/second", addresses_per_second as u64);
    println!("Expected attempts to find zero address: 2^160 ≈ {:.2e}", expected_attempts);
    
    time_millennia
}

#[derive(Parser, Debug)]
#[command(name = "zero-address-contract")]
#[command(about = "Generate ECDSA keys and search for CREATE2 addresses with trailing zeros")]
struct Args {
    /// Calculate and report expected time in millennia to find zero address
    #[arg(short = 't', long)]
    time_estimate: bool,
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
    let args = Args::parse();
    
    println!("{}", "=".repeat(70));
    println!("ECDSA Key Generation and CREATE2 Address Search");
    println!("{}", "=".repeat(70));
    println!();
    
    // Step 1: Load or generate private key and public key
    println!("Step 1: Loading or generating ECDSA key pair...");
    let (secret_key, public_key, is_new, loaded_first_contract_address) = load_or_generate_keys();
    
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
    
    // SimpleProxy contract init code (bytecode + constructor args)
    // Constructor arg: address(0) which defaults to 0x2c36dd7Bb3E95E7a0219E70737eE8041f22d2081
    // Read from init_code.txt (generated by get_init_code.js from compiled contract)
    let init_code = match std::fs::read_to_string("init_code.txt") {
        Ok(contents) => {
            let hex_str = contents.trim();
            hex::decode(hex_str).expect("Failed to decode init code hex from init_code.txt")
        }
        Err(e) => {
            eprintln!("Error reading init_code.txt: {}", e);
            eprintln!("Please run 'npm run compile' and 'node get_init_code.js' first.");
            return;
        }
    };
    
    // If -t flag is set, calculate and report time estimate
    if args.time_estimate {
        println!("{}", "=".repeat(70));
        println!("Time Estimate for Zero Address (all 20 bytes = 0x00)");
        println!("{}", "=".repeat(70));
        println!();
        println!("Benchmarking computation speed...");
        // Compute CREATE2Deployer factory address first
        let factory_address = compute_create_address(&deployer_address, 0);
        let time_millennia = calculate_zero_address_time(&factory_address, &init_code, 100000);
        println!();
        println!("Expected time to find zero address: {:.2e} millennia", time_millennia);
        println!("(This is approximately {:.2e} times the age of the universe)", 
                 time_millennia / 13.8); // Universe is ~13.8 billion years old
        println!();
        return;
    }
    
    // Step 3: Compute CREATE2Deployer factory address (deployed from EOA using CREATE, nonce 0)
    println!("Step 3: Computing CREATE2Deployer factory address...");
    let factory_address = compute_create_address(&deployer_address, 0);
    let factory_address_hex = to_checksum_address(&factory_address);
    println!("CREATE2Deployer factory address (from EOA, nonce 0): 0x{}", factory_address_hex);
    println!();
    
    // Step 4: Search for CREATE2 address with most trailing zeros
    println!("Step 4: Searching for CREATE2 address with most trailing zeros...");
    println!("Using SimpleProxy contract init code ({} bytes)", init_code.len());
    println!("Constructor arg: address(0) -> defaults to 0x2c36dd7Bb3E95E7a0219E70737eE8041f22d2081");
    println!("Using factory address as deployer in CREATE2: 0x{}", factory_address_hex);
    println!();
    
    // Compute first CREATE2 address (salt = 0, which is 32 bytes of zeros)
    // Use factory_address, not deployer_address (EOA)
    let first_salt = [0u8; 32];
    let first_contract_address = compute_create2_address(&factory_address, &first_salt, &init_code);
    let first_contract_address_hex = to_checksum_address(&first_contract_address);
    println!("First CREATE2 Address (salt=0): 0x{}", first_contract_address_hex);
    
    // Verify or save the first contract address
    if let Some(loaded_addr) = loaded_first_contract_address {
        // Verify that the computed address matches the loaded one
        if first_contract_address != loaded_addr {
            let loaded_addr_hex = to_checksum_address(&loaded_addr);
            eprintln!("ERROR: Computed firstContractAddress (0x{}) does not match", first_contract_address_hex);
            eprintln!("       the one in myaddress.dat (0x{})", loaded_addr_hex);
            return;
        }
        println!("Verified: Computed firstContractAddress matches the one in myaddress.dat");
    } else if is_new {
        // Only save when generating new keys
        match save_keys_to_file(&secret_key, &public_key, Some(&first_contract_address)) {
            Ok(()) => {
                println!("Saved firstContractAddress to myaddress.dat");
            }
            Err(e) => {
                eprintln!("Warning: Failed to save firstContractAddress to myaddress.dat: {}", e);
            }
        }
    }
    println!();
    
    let mut salt = [0u8; 32];
    let mut best_salt = salt;
    let mut best_address = first_contract_address;
    let mut best_trailing_zeros = count_trailing_zeros(&best_address);
    let mut best_leading_zeros = count_leading_zeros(&best_address);
    let mut best_score = best_leading_zeros + best_trailing_zeros;
    let mut checked = 0u64;
    
    println!("Searching through salt values...");
    println!(
        "Current best: leading={} trailing={} (score={}) at salt 0x{}",
        best_leading_zeros,
        best_trailing_zeros,
        best_score,
        hex::encode(best_salt)
    );
    
    // Search through salt values
    loop {
        let contract_address = compute_create2_address(&factory_address, &salt, &init_code);
        let trailing_zeros = count_trailing_zeros(&contract_address);
        let leading_zeros = count_leading_zeros(&contract_address);
        let score = leading_zeros + trailing_zeros;
        
        if score > best_score
            || (score == best_score
                && (trailing_zeros > best_trailing_zeros
                    || (trailing_zeros == best_trailing_zeros
                        && leading_zeros > best_leading_zeros)))
        {
            best_score = score;
            best_trailing_zeros = trailing_zeros;
            best_leading_zeros = leading_zeros;
            best_salt = salt;
            best_address = contract_address;
            let best_address_hex = to_checksum_address(&best_address);
            println!(
                "New best: leading={} trailing={} (score={}) at salt 0x{} -> 0x{}",
                best_leading_zeros,
                best_trailing_zeros,
                best_score,
                hex::encode(best_salt),
                best_address_hex
            );
        }
        
        checked += 1;
        if checked % 100000 == 0 {
            print!(
                "Checked {} salts... (best score={}, leading={}, trailing={})\r",
                checked, best_score, best_leading_zeros, best_trailing_zeros
            );
            io::stdout().flush().unwrap();
        }
        
        increment_salt(&mut salt);
        
        // Stop if we find an address with 20 trailing and leading zeros (all zeros, very unlikely)
        if best_trailing_zeros >= 20 && best_leading_zeros >= 20 {
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
    println!("Leading Zeros:    {} bytes", best_leading_zeros);
    println!("Trailing Zeros:   {} bytes", best_trailing_zeros);
    println!("Score (L+T):      {} bytes", best_score);
    println!("CREATE2 Address:  0x{}", best_address_hex);
    println!("Address (hex):    0x{}", hex::encode(best_address));
    println!();
    println!("Searched through {} salt values", checked);
}

