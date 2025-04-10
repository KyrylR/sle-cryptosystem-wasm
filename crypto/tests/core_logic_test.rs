use crypto::keypair::{PrivateKey, PublicKey};
use crypto::system::errors::CryptoError;
use crypto::system::matrix_ops::Vector;
use crypto::system::{decrypt, encrypt};

// Define constants for tests
const TEST_M: u64 = 25;
const TEST_P: usize = 2;
const TEST_Q: usize = 4;
const TEST_SEED: u64 = 42;
const TEST_ENCRYPT_SEED: u64 = 123;

#[test]
fn test_basic_encryption_decryption() -> Result<(), CryptoError> {
    println!("\n--- Testing Basic Block Encryption/Decryption ---");
    // 1. Generate keys using the standard method
    let private_key = PrivateKey::generate(TEST_M, TEST_P, TEST_Q, TEST_SEED)?;
    let public_key = &private_key.public_key;

    // 2. Define a message block
    let message_block: Vector = vec![18, 0]; // Example block
    assert_eq!(message_block.len(), public_key.shared.p);
    println!("Original Block: {:?}", message_block);

    // 3. Encrypt
    let (d, d1) = encrypt(public_key, &message_block, TEST_ENCRYPT_SEED)?;
    assert_eq!(d.len(), public_key.shared.p);
    assert_eq!(d1.len(), public_key.shared.p);
    println!("Ciphertext (d, d1): ({:?}, {:?})", d, d1);

    // 4. Decrypt
    let decrypted_block = decrypt(&private_key, &d, &d1)?;
    println!("Decrypted Block: {:?}", decrypted_block);

    // 5. Verify
    assert_eq!(decrypted_block, message_block);
    println!("Basic Block Test Successful!");

    Ok(())
}

#[test]
fn test_multiple_block_encryption() -> Result<(), CryptoError> {
    println!("\n--- Testing Multiple Block Encryption/Decryption ---");
    let private_key = PrivateKey::generate(TEST_M, TEST_P, TEST_Q, TEST_SEED)?;
    let public_key = &private_key.public_key;

    let message1: Vector = vec![1, 2];
    let message2: Vector = vec![0, 3];

    println!("Block 1 Original: {:?}", message1);
    let (d1, d1_1) = encrypt(public_key, &message1, TEST_ENCRYPT_SEED)?;
    println!("Block 1 Ciphertext: ({:?}, {:?})", d1, d1_1);

    println!("Block 2 Original: {:?}", message2);
    let (d2, d1_2) = encrypt(public_key, &message2, TEST_ENCRYPT_SEED + 1)?;
    println!("Block 2 Ciphertext: ({:?}, {:?})", d2, d1_2);

    // Encrypt block 1 again with a different seed
    println!("Block 3 Original (Same as Block 1): {:?}", message1);
    let (d3, d1_3) = encrypt(public_key, &message1, TEST_ENCRYPT_SEED + 2)?;
    println!("Block 3 Ciphertext: ({:?}, {:?})", d3, d1_3);

    // Ensure ciphertexts differ with different seeds
    assert_ne!(
        (d1.clone(), d1_1.clone()),
        (d3.clone(), d1_3.clone()),
        "Ciphertexts should differ with different seeds"
    );

    // Decrypt all blocks
    let dec1 = decrypt(&private_key, &d1, &d1_1)?;
    println!("Block 1 Decrypted: {:?}", dec1);
    let dec2 = decrypt(&private_key, &d2, &d1_2)?;
    println!("Block 2 Decrypted: {:?}", dec2);
    let dec3 = decrypt(&private_key, &d3, &d1_3)?;
    println!("Block 3 Decrypted: {:?}", dec3);

    assert_eq!(dec1, message1);
    assert_eq!(dec2, message2);
    assert_eq!(dec3, message1);
    println!("Multiple Block Test Successful!");

    Ok(())
}

#[test]
fn test_key_serialization_integration() -> Result<(), CryptoError> {
    println!("\n--- Testing Key Serialization/Deserialization Integration ---");
    let private_key_orig = PrivateKey::generate(TEST_M, TEST_P, TEST_Q, TEST_SEED)?;
    let public_key_orig = private_key_orig.public_key.clone();
    println!("Original Private Key Generated.");

    let priv_json = private_key_orig.to_json()?;
    let pub_json = public_key_orig.to_json()?;
    println!("Keys Serialized to JSON.");
    // println!("Private JSON: {}", priv_json); // Optional: for debugging
    // println!("Public JSON: {}", pub_json);

    let private_key_deser = PrivateKey::from_json(&priv_json)?;
    let public_key_deser = PublicKey::from_json(&pub_json)?;
    println!("Keys Deserialized from JSON.");

    // Check basic field equality after deserialization
    assert_eq!(public_key_deser.shared.m, public_key_orig.shared.m);
    assert_eq!(public_key_deser.shared.p, public_key_orig.shared.p);
    assert_eq!(public_key_deser.shared.q, public_key_orig.shared.q);
    assert_eq!(
        public_key_deser.encryption_params,
        public_key_orig.encryption_params
    );
    assert_eq!(
        private_key_deser.decryption_secrets,
        private_key_orig.decryption_secrets
    );
    assert_eq!(
        private_key_deser.public_key.shared.m,
        private_key_orig.public_key.shared.m
    );
    assert_eq!(
        private_key_deser.public_key.encryption_params,
        private_key_orig.public_key.encryption_params
    );
    println!("Deserialized key fields match original.");

    // Test encryption/decryption with deserialized keys
    let message_block: Vector = vec![2, 3]; // Example block
    println!(
        "Encrypting block {:?} using deserialized public key.",
        message_block
    );
    let (d, d1) = encrypt(&public_key_deser, &message_block, TEST_ENCRYPT_SEED)?;
    println!("Ciphertext: ({:?}, {:?})", d, d1);

    println!("Decrypting using deserialized private key.");
    let decrypted_block = decrypt(&private_key_deser, &d, &d1)?;
    println!("Decrypted Block: {:?}", decrypted_block);

    assert_eq!(decrypted_block, message_block);
    println!("Encryption/Decryption with deserialized keys successful!");
    println!("Key Serialization Integration Test Successful!");

    Ok(())
}

#[test]
fn test_setup_failure_q_less_than_p() -> Result<(), CryptoError> {
    println!("\n--- Testing Key Generation Failure (q < p) ---");
    let result = PrivateKey::generate(25, 2, 1, 123); // q < p
    println!("Result of generating keys with q < p: {:?}", result);
    assert!(matches!(result, Err(CryptoError::InvalidParameters(_))));
    // We expect an error, so returning Ok(()) if the assertion passes.
    println!("Key Generation Failure (q < p) Test Successful!");
    Ok(())
}

#[test]
fn test_setup_failure_invalid_modulus() -> Result<(), CryptoError> {
    println!("\n--- Testing Key Generation Failure (m <= 1) ---");
    let result = PrivateKey::generate(1, TEST_P, TEST_Q, TEST_SEED); // m = 1
    println!("Result of generating keys with m=1: {:?}", result);
    assert!(matches!(result, Err(CryptoError::InvalidParameters(_))));
    let result_m0 = PrivateKey::generate(0, TEST_P, TEST_Q, TEST_SEED); // m = 0
    println!("Result of generating keys with m=0: {:?}", result_m0);
    assert!(matches!(result_m0, Err(CryptoError::InvalidParameters(_))));
    println!("Key Generation Failure (m <= 1) Test Successful!");
    Ok(())
}

#[test]
fn test_setup_failure_p_zero() -> Result<(), CryptoError> {
    println!("\n--- Testing Key Generation Failure (p = 0) ---");
    let result = PrivateKey::generate(TEST_M, 0, TEST_Q, TEST_SEED); // p = 0
    println!("Result of generating keys with p=0: {:?}", result);
    assert!(matches!(result, Err(CryptoError::InvalidParameters(_))));
    println!("Key Generation Failure (p = 0) Test Successful!");
    Ok(())
}
