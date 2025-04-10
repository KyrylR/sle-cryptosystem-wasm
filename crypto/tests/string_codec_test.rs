use crypto::codec::{decrypt_string, encrypt_string};
use crypto::keypair::PrivateKey;
use crypto::system::errors::CryptoError;

#[test]
fn test_string_encrypt_decrypt() -> Result<(), CryptoError> {
    println!("\n--- Testing String Encryption/Decryption ---");

    // Parameters (Need m >= 256 for byte encoding)
    let m = 257; // Prime modulus >= 256
    let p = 8; // Block size (bytes per vector)
    let q = 10; // Must be >= p
    let setup_seed = 54321u64;

    // Setup
    let private_key = PrivateKey::generate(m, p, q, setup_seed)?;
    let public_key = private_key.public_key.clone();

    println!("Keys generated (m={}, p={}, q={})", m, p, q);

    // Message
    let original_message = "This is a test message for the cryptosystem.";
    println!("Original String: {}", original_message);

    // Encryption
    let ciphertext_bytes = encrypt_string(&public_key, original_message)?;
    println!("Ciphertext Bytes Length: {}", ciphertext_bytes.len());
    // Optional: Print some bytes for visual check
    println!(
        "Ciphertext Bytes (first 32): {:?}...",
        ciphertext_bytes.iter().take(32).collect::<Vec<_>>()
    );

    // Decryption
    let decrypted_string = decrypt_string(&private_key, &ciphertext_bytes)?;
    println!("Decrypted String: {}", decrypted_string);

    // Verification
    assert_eq!(
        decrypted_string, original_message,
        "Decrypted string does not match original message!"
    );

    println!("\nString Encryption/Decryption Test Successful!");

    Ok(())
}

#[test]
fn test_string_encrypt_decrypt_padding() -> Result<(), CryptoError> {
    println!("\n--- Testing String Encryption/Decryption (Padding Cases) ---");
    let m = 257;
    let p = 16;
    let q = 20;
    let setup_seed = 65432u64;

    // Setup
    let private_key = PrivateKey::generate(m, p, q, setup_seed)?;
    let public_key = private_key.public_key.clone();

    let messages = [
        "Short",                                  // Needs padding
        "Exactly one block", // Needs padding (to fill the last block entirely with padding)
        "This is slightly longer than one block", // Needs padding
        "",                  // Empty string, should result in a padded block
    ];

    for original_message in &messages {
        println!("\nTesting message: \"{}\"", original_message);
        let ciphertext_bytes = encrypt_string(&public_key, original_message)?;
        let decrypted_string = decrypt_string(&private_key, &ciphertext_bytes)?;
        println!("Decrypted: \"{}\"", decrypted_string);
        assert_eq!(
            &decrypted_string, original_message,
            "Padding test failed for message: {}",
            original_message
        );
    }

    println!("\nString Padding Tests Successful!");
    Ok(())
}

#[test]
fn test_decrypt_invalid_ciphertext() -> Result<(), CryptoError> {
    println!("\n--- Testing Decryption with Invalid Ciphertext ---");
    let m = 257;
    let p = 8;
    let q = 10;
    let setup_seed = 76543u64;

    // Setup
    let private_key = PrivateKey::generate(m, p, q, setup_seed)?;
    let public_key = private_key.public_key.clone(); // Need public key to encrypt for tests

    // Case 1: Too short ciphertext
    let short_ciphertext = vec![0u8; 3];
    let result1 = decrypt_string(&private_key, &short_ciphertext);
    println!("Decrypting too short: {:?}", result1);
    assert!(
        matches!(result1, Err(CryptoError::DeserializationError(_))),
        "Failed Case 1: Too short"
    );

    // Case 2: Invalid padding byte value
    let message = "test";
    let mut valid_ciphertext = encrypt_string(&public_key, message)?;
    // Corrupt the last byte (which should be a padding byte)
    if let Some(last_byte) = valid_ciphertext.last_mut() {
        // Ensure p is reasonably small for this test logic
        assert!(p < 99, "Test logic assumes p < 99 for invalid padding byte");
        *last_byte = 99; // Assuming p < 99, this is an invalid padding value
    }
    let result2 = decrypt_string(&private_key, &valid_ciphertext);
    println!("Decrypting invalid padding byte: {:?}", result2);
    // Expecting DecodingError because unpadding fails
    assert!(
        matches!(result2, Err(CryptoError::DecodingError(_))),
        "Failed Case 2: Invalid padding"
    );

    // Case 3: Data length not multiple of required size after deserialization
    // The internal `deserialize_ciphertext` expects a specific structure.
    // Let's encrypt something, get the valid ciphertext, and then truncate it
    // in a way that breaks the structure.
    let message_long = "another test string for truncation";
    let mut truncated_ciphertext = encrypt_string(&public_key, message_long)?;
    // Remove one byte to make the length invalid for deserialization
    truncated_ciphertext.pop();
    let result3 = decrypt_string(&private_key, &truncated_ciphertext);
    println!("Decrypting truncated ciphertext: {:?}", result3);
    assert!(
        matches!(result3, Err(CryptoError::DeserializationError(_))),
        "Failed Case 3: Truncated"
    );

    println!("\nInvalid Ciphertext Tests Successful!");
    Ok(())
}
