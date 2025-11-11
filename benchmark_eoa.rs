use secp256k1::{Secp256k1, SecretKey, PublicKey};
use sha3::{Keccak256, Digest};
use rand::rngs::OsRng;
use std::time::Instant;

/// Compute Keccak-256 hash
fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
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

/// Increment a 32-byte salt by 1 (wrapping around if needed)
fn increment_salt(salt: &mut [u8; 32]) {
    for i in (0..32).rev() {
        salt[i] = salt[i].wrapping_add(1);
        if salt[i] != 0 {
            break;
        }
    }
}

/// Derive Ethereum address from public key
/// Ethereum address is the last 20 bytes of Keccak-256 hash of the public key
fn derive_ethereum_address(public_key: &PublicKey) -> [u8; 20] {
    // Get uncompressed public key (65 bytes: 0x04 + 64 bytes)
    let public_key_bytes = public_key.serialize_uncompressed();
    // Remove the 0x04 prefix (first byte)
    let public_key_no_prefix = &public_key_bytes[1..];
    
    // Hash with Keccak-256
    let mut hasher = Keccak256::new();
    hasher.update(public_key_no_prefix);
    let hash = hasher.finalize();
    
    // Take last 20 bytes
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    address
}

/// Increment a 32-byte secret key by 1 (wrapping around if needed)
fn increment_secret_key(secret_key: &mut SecretKey) {
    let mut bytes = secret_key.secret_bytes();
    
    // Increment from the rightmost byte
    for i in (0..32).rev() {
        bytes[i] = bytes[i].wrapping_add(1);
        if bytes[i] != 0 {
            break;
        }
    }
    
    // Create new secret key from incremented bytes
    *secret_key = SecretKey::from_slice(&bytes).expect("Invalid secret key");
}

fn main() {
    println!("Ethereum EOA Address Generation Benchmark");
    println!("==========================================");
    println!();
    
    // Initialize secp256k1 context
    let secp = Secp256k1::new();
    
    // Generate initial random private key
    let mut rng = OsRng;
    let mut secret_key = SecretKey::new(&mut rng);
    
    println!("Starting with random private key");
    println!("Generating 1000 Ethereum addresses...");
    println!();
    
    // Benchmark
    let start = Instant::now();
    
    for i in 0..1000 {
        // Derive public key from private key
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        
        // Derive Ethereum address
        let _address = derive_ethereum_address(&public_key);
        
        // Increment private key for next iteration
        if i < 999 {
            increment_secret_key(&mut secret_key);
        }
    }
    
    let elapsed = start.elapsed();
    let total_nanos = elapsed.as_nanos();
    let total_seconds = elapsed.as_secs_f64();
    
    // Calculate averages
    let avg_nanos = total_nanos / 1000;
    let avg_micros = avg_nanos as f64 / 1000.0;
    let avg_millis = avg_micros / 1000.0;
    let addresses_per_second = 1000.0 / total_seconds;
    
    println!("Results:");
    println!("=========");
    println!("Total addresses generated: 1000");
    println!("Total time: {:.2} seconds ({:.2} ms)", total_seconds, total_seconds * 1000.0);
    println!();
    println!("Average time per address:");
    println!("  {:.2} nanoseconds", avg_nanos as f64);
    println!("  {:.2} microseconds", avg_micros);
    println!("  {:.3} milliseconds", avg_millis);
    println!();
    println!("Throughput: {:.2} addresses/second", addresses_per_second);
    println!();
    
    println!();
    println!("{}", "=".repeat(50));
    println!("CREATE2 Address Generation Benchmark");
    println!("{}", "=".repeat(50));
    println!();
    
    // Use the first generated EOA address as deployer for CREATE2
    let first_secret_key = SecretKey::new(&mut OsRng);
    let first_public_key = PublicKey::from_secret_key(&secp, &first_secret_key);
    let deployer_address = derive_ethereum_address(&first_public_key);
    
    let init_code = b""; // Empty init code for comparison
    let mut salt = [0u8; 32];
    
    println!("Using deployer address from first EOA");
    println!("Generating 1000 CREATE2 addresses...");
    println!();
    
    // Benchmark CREATE2
    let start_create2 = Instant::now();
    
    for _ in 0..1000 {
        // Compute CREATE2 address
        let _address = compute_create2_address(&deployer_address, &salt, init_code);
        
        // Increment salt for next iteration
        increment_salt(&mut salt);
    }
    
    let elapsed_create2 = start_create2.elapsed();
    let total_nanos_create2 = elapsed_create2.as_nanos();
    let total_seconds_create2 = elapsed_create2.as_secs_f64();
    
    // Calculate averages for CREATE2
    let avg_nanos_create2 = total_nanos_create2 / 1000;
    let avg_micros_create2 = avg_nanos_create2 as f64 / 1000.0;
    let avg_millis_create2 = avg_micros_create2 / 1000.0;
    let addresses_per_second_create2 = 1000.0 / total_seconds_create2;
    
    println!("Results:");
    println!("=========");
    println!("Total addresses generated: 1000");
    println!("Total time: {:.2} seconds ({:.2} ms)", total_seconds_create2, total_seconds_create2 * 1000.0);
    println!();
    println!("Average time per address:");
    println!("  {:.2} nanoseconds", avg_nanos_create2 as f64);
    println!("  {:.2} microseconds", avg_micros_create2);
    println!("  {:.3} milliseconds", avg_millis_create2);
    println!();
    println!("Throughput: {:.2} addresses/second", addresses_per_second_create2);
    println!();
    
    // Comparison
    println!("{}", "=".repeat(50));
    println!("Comparison");
    println!("{}", "=".repeat(50));
    println!();
    let speedup = addresses_per_second_create2 / addresses_per_second;
    println!("CREATE2 is {:.2}x faster than EOA generation", speedup);
    println!();
    println!("EOA:      {:.2} addresses/second ({:.2} μs/address)", addresses_per_second, avg_micros);
    println!("CREATE2:  {:.2} addresses/second ({:.2} μs/address)", addresses_per_second_create2, avg_micros_create2);
    println!();
    println!("This explains why finding a zero address contract via CREATE2");
    println!("is more feasible than finding a zero address EOA, even though");
    println!("both have the same probability (1 in 2^160).");
}

