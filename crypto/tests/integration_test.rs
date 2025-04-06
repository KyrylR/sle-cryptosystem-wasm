// Make sure your crate root (lib.rs or main.rs) exposes the crypto module
// e.g., `pub mod crypto;`
// and potentially re-exports: `pub use crypto::*;`

use crypto::Ring;
use crypto::system::decrypt;
use crypto::system::errors::CryptoError;
use crypto::system::matrix_ops::{Matrix, Vector, matrix_inverse, matrix_vector_mul, vector_add};
use crypto::system::params::{AliceSecret, SharedParams, PublicKey, PrivateKey};
use crypto::system::{encrypt, setup_shared};
use crypto::{encrypt_string, decrypt_string};

#[test]
fn test_example_3_decryption_step() -> Result<(), CryptoError> {
    println!("\n--- Testing Example 3 Decryption Step 1 (Corrected) ---");

    // --- Parameters from Example 3 ---
    let m = 25u64;
    let p = 2usize; // Number of equations (block size)
    let q = 4usize; // Number of variables (dummy for this test)
    let ring = Ring::try_with(m)?;

    // --- Define Alice's Parameters based on Example 3 (using Z_25 mapping) ---
    // Renamed B_bar -> b_bar
    let b_bar: Matrix = vec![vec![2, 1], vec![24, 24]]; // This is B in Z_25

    // Inner constant vector a_inner (added inside B1) = [1, 2] in Z_25
    let a_inner: Vector = vec![1, 2];
    // Outer constant vector a_outer (subtracted from d1 in decryption) = [7, 19] in Z_25
    let a_outer: Vector = vec![7, 19];

    // Calculate b_bar_inv (Alice's Secret) - Renamed variables
    let b_bar_inv = matrix_inverse(&b_bar, &ring)?;
    let expected_b_bar_inv: Matrix = vec![vec![1, 1], vec![24, 23]]; // Matches paper's B1_inv mod 25
    assert_eq!(
        b_bar_inv, expected_b_bar_inv,
        "Calculated b_bar_inv does not match example"
    );
    println!("Verified b_bar_inv (in Z_25): {:?}", b_bar_inv);

    // Setup Structs for Decryption Call - Use snake_case field b_inv
    let shared_params = SharedParams { m, ring, p, q };
    let alice_secret = AliceSecret {
        b_inv: b_bar_inv, // Use the inverse of the Z_25 matrix
        a_inner,
        a_outer,
    };

    // Data from Example 3's First Encryption
    let original_message: Vector = vec![18, 0];
    let d: Vector = vec![2, 15];
    let d1: Vector = vec![16, 6]; // CORRECTED d1

    println!("Original Message (v): {:?}", original_message);
    println!("Using Corrected Ciphertext (d, d1): ({:?}, {:?})", d, d1);

    // --- Decryption using the corrected function ---
    let decrypted_block = decrypt(&shared_params, &alice_secret, &d, &d1)?;
    println!("Decrypted Message Block: {:?}", decrypted_block);

    // --- Verification ---
    assert_eq!(
        decrypted_block, original_message,
        "Decrypted block does not match original message!"
    );

    println!("\nExample 3 Decryption Step Test (Corrected Logic & Ciphertext) Successful!");

    Ok(())
}

#[test]
fn test_example_3_encryption_step() -> Result<(), CryptoError> {
    println!("\n--- Testing Example 3 Encryption Step (Corrected Logic) ---");

    // --- Parameters from Example 3 ---
    let m = 25u64;
    let _p = 2usize; // Block size (unused in direct calculation, prefix with _)
    let ring = Ring::try_with(m)?;

    // --- Alice's Secret Parameters (Publicly known parts for Bob's L construction) ---
    // Renamed B_bar -> b_bar
    let b_bar: Matrix = vec![vec![2, 1], vec![24, 24]]; // B1 from Example 3, in Z_25
    let a_inner: Vector = vec![1, 2];
    let a_outer: Vector = vec![7, 19];

    // --- Bob's Public Parameters (Matrix A from l_hat(x)) ---
    // Renamed A -> a_matrix
    let a_matrix: Matrix = vec![vec![5, 6, 9, 21], vec![0, 1, 11, 14]]; // A from l_hat in Example 3

    // --- Bob's Calculation Inputs ---
    let v: Vector = vec![18, 0];
    let a_rand: Vector = vec![0, 1, 0, 1];

    // --- Correct Encryption Steps (Following Protocol) ---

    // 1. Calculate d = l_hat(a_rand) = A * a_rand - Use a_matrix
    let d = matrix_vector_mul(&a_matrix, &a_rand, &ring)?;
    let expected_d_from_example: Vector = vec![2, 15];
    println!("Calculated d = A * a_rand: {:?}", d);
    assert_eq!(
        d, expected_d_from_example,
        "Calculated d does not match example"
    );

    // 2. Calculate d1 = B_bar * (v + d + a_inner) + a_outer - Use b_bar
    let v_plus_d = vector_add(&v, &d, &ring)?;
    let inner_term = vector_add(&v_plus_d, &a_inner, &ring)?;
    // Renamed B_mult -> b_mult
    let b_mult = matrix_vector_mul(&b_bar, &inner_term, &ring)?;
    let d1 = vector_add(&b_mult, &a_outer, &ring)?;

    // Expected d1 (Calculated manually in previous step)
    let expected_d1_corrected: Vector = vec![16, 6];
    println!("Calculated d1 (Corrected Logic): {:?}", d1);
    println!("Expected d1 (Corrected Logic): {:?}", expected_d1_corrected);
    assert_eq!(
        d1, expected_d1_corrected,
        "Calculated d1 does not match expected value from corrected logic"
    );

    // --- Assemble Ciphertext ---
    let ciphertext = (d, d1);
    let expected_ciphertext_corrected = (expected_d_from_example, expected_d1_corrected);
    println!(
        "Final Ciphertext (d, d1) (Corrected Logic): {:?}",
        ciphertext
    );

    assert_eq!(
        ciphertext.0, expected_ciphertext_corrected.0,
        "Ciphertext d component mismatch"
    );
    assert_eq!(
        ciphertext.1, expected_ciphertext_corrected.1,
        "Ciphertext d1 component mismatch"
    );

    println!("\nExample 3 Encryption Step Test (Corrected Logic) Successful!");

    Ok(())
}

#[test]
fn test_full_encrypt_decrypt_cycle() -> Result<(), CryptoError> {
    // --- Parameters ---
    let m = 25u64; // Modulus from paper example
    let p = 2usize; // Block size (number of equations)
    let q = 4usize; // Number of variables
    let setup_seed = 12345u64;
    let encrypt_seed = 67890u64; // Different seed for encryption randomness

    // --- Setup ---
    let (shared_params, alice_secret, bob_public) =
        setup_shared(m, p, q, setup_seed)?;

    println!("Setup Complete:");
    println!("  Modulus m: {}", shared_params.m);
    println!("  Block size p: {}", shared_params.p);
    println!("  Variables q: {}", shared_params.q);
    println!("  Alice Secret b_inv: {:?}", alice_secret.b_inv); // For debug
    println!("  Bob Public a: {:?}", bob_public.a); // For debug
    println!("  Bob Public b: {:?}", bob_public.b); // For debug

    // --- Message ---
    // Example message block "ta" -> (18, 0) from paper's table
    let message_block: Vector = vec![18, 0];
    println!("\nOriginal Message Block: {:?}", message_block);


    // --- Encryption ---
    let ciphertext = encrypt(&shared_params, &bob_public, &message_block, encrypt_seed)?;
    println!("Ciphertext (d, d1): ({:?}, {:?})", ciphertext.0, ciphertext.1);

    // --- Decryption ---
    let decrypted_block = decrypt(&shared_params, &alice_secret, &ciphertext.0, &ciphertext.1)?;
    println!("Decrypted Message Block: {:?}", decrypted_block);


    // --- Verification ---
    assert_eq!(
        decrypted_block, message_block,
        "Decrypted block does not match original message block!"
    );

    println!("\nEncryption/Decryption Cycle Successful!");

    Ok(())
}

#[test]
fn test_multiple_blocks() -> Result<(), CryptoError> {
     // --- Parameters ---
    let m = 31u64; // Use a prime modulus for easier inversion/solving
    let p = 3usize;
    let q = 5usize;
    let setup_seed = 999u64;

    // --- Setup ---
    let (shared_params, alice_secret, bob_public) =
        setup_shared(m, p, q, setup_seed)?;

    // --- Message (multiple blocks) ---
    let message = vec![
        vec![10, 20, 5], // Block 1
        vec![1, 2, 3],   // Block 2
        vec![0, 0, 0],   // Block 3
        vec![30, 15, 25], // Block 4
    ];

    println!("Testing multiple blocks (m={}, p={}, q={})", m, p, q);

    for (i, original_block) in message.iter().enumerate() {
        let encrypt_seed = 1000 + i as u64; // Use different seed per block
        println!("\nBlock {}:", i + 1);
        println!("  Original: {:?}", original_block);

        let ciphertext = encrypt(&shared_params, &bob_public, original_block, encrypt_seed)?;
        println!("  Ciphertext: ({:?}, {:?})", ciphertext.0, ciphertext.1);

        let decrypted_block = decrypt(&shared_params, &alice_secret, &ciphertext.0, &ciphertext.1)?;
        println!("  Decrypted: {:?}", decrypted_block);

        assert_eq!(
            &decrypted_block, original_block,
            "Decryption failed for block {}!", i + 1
        );
    }
     println!("\nMultiple Block Test Successful!");
    Ok(())
}

#[test]
fn test_setup_failure_q_less_than_p() -> Result<(), CryptoError> {
     // Uses setup_shared
     let result = setup_shared(25, 4, 3, 123); // q < p
     assert!(matches!(result, Err(CryptoError::InvalidParameters(_))));
     // We expect an error, so returning Ok(()) if the assertion passes.
     // If setup_shared succeeded, the assertion would fail, causing the test to fail.
     Ok(())
}

#[test]
fn test_string_encrypt_decrypt() -> Result<(), CryptoError> {
    println!("\n--- Testing String Encryption/Decryption ---");

    // --- Parameters (Need m >= 256 for byte encoding) ---
    let m = 257; // Prime modulus >= 256
    let p = 8;  // Block size (bytes per vector)
    let q = 10; // Must be >= p
    let setup_seed = 54321u64;

    // --- Setup --- 
    let (shared_params, alice_secret, bob_public) = setup_shared(m, p, q, setup_seed)?;

    let public_key = PublicKey {
        shared: shared_params.clone(), // Clone shared params
        bob_public,
    };
    let private_key = PrivateKey {
        shared: shared_params, // Move the last shared params
        alice_secret,
    };

    println!("Keys generated (m={}, p={}, q={})", m, p, q);

    // --- Message ---
    let original_message = "This is a test message for the cryptosystem.";
    println!("Original String: {}", original_message);

    // --- Encryption ---
    let ciphertext_bytes = encrypt_string(&public_key, original_message)?;
    println!("Ciphertext Bytes Length: {}", ciphertext_bytes.len());
    // Optional: Print some bytes for visual check
    println!("Ciphertext Bytes (first 32): {:?}...", ciphertext_bytes.iter().take(32).collect::<Vec<_>>());

    // --- Decryption ---
    let decrypted_string = decrypt_string(&private_key, &ciphertext_bytes)?;
    println!("Decrypted String: {}", decrypted_string);

    // --- Verification ---
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

    let (shared_params, alice_secret, bob_public) = setup_shared(m, p, q, setup_seed)?;
    let public_key = PublicKey { shared: shared_params.clone(), bob_public };
    let private_key = PrivateKey { shared: shared_params, alice_secret };

    let messages = [
        "Short", // Needs padding
        "Exactly one block", // Needs padding (to fill the last block entirely with padding)
        "This is slightly longer than one block", // Needs padding
        "", // Empty string, should result in a padded block
    ];

    for original_message in &messages {
        println!("\nTesting message: \"{}\"", original_message);
        let ciphertext_bytes = encrypt_string(&public_key, original_message)?;
        let decrypted_string = decrypt_string(&private_key, &ciphertext_bytes)?;
        println!("Decrypted: \"{}\"", decrypted_string);
        assert_eq!(
            &decrypted_string, original_message,
            "Padding test failed for message: {}", original_message
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

    let (shared_params, alice_secret, _bob_public) = setup_shared(m, p, q, setup_seed)?;
    let private_key = PrivateKey { shared: shared_params, alice_secret };

    // Case 1: Too short
    let short_ciphertext = vec![0u8; 3];
    let result1 = decrypt_string(&private_key, &short_ciphertext);
    println!("Decrypting too short: {:?}", result1);
    assert!(matches!(result1, Err(CryptoError::DeserializationError(_))));

    // Case 2: Invalid padding byte value
    let message = "test";
    let mut valid_ciphertext = encrypt_string(&PublicKey { shared: private_key.shared.clone(), bob_public: _bob_public.clone() }, message)?;
    *valid_ciphertext.last_mut().unwrap() = 99; // Invalid padding value
    let result2 = decrypt_string(&private_key, &valid_ciphertext);
    println!("Decrypting invalid padding byte: {:?}", result2);
    assert!(matches!(result2, Err(CryptoError::DecodingError(_))));

    // Case 3: Data length not multiple of block pair size
    let mut truncated_ciphertext = encrypt_string(&PublicKey { shared: private_key.shared.clone(), bob_public: _bob_public.clone() }, "another test")?;
    truncated_ciphertext.pop(); // Make length invalid
    let result3 = decrypt_string(&private_key, &truncated_ciphertext);
    println!("Decrypting truncated ciphertext: {:?}", result3);
    assert!(matches!(result3, Err(CryptoError::DeserializationError(_))));

    println!("\nInvalid Ciphertext Tests Successful!");
    Ok(())
}
