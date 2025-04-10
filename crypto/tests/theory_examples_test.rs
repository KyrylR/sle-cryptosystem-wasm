use crypto::Ring;
use crypto::keypair::{DecryptionSecrets, PrivateKey, PublicKey, SharedParams};
use crypto::system::decrypt;
use crypto::system::errors::CryptoError;
use crypto::system::matrix_ops::{Matrix, Vector, matrix_inverse, matrix_vector_mul, vector_add};

#[test]
fn test_example_3_decryption_step() -> Result<(), CryptoError> {
    println!(
        "
--- Testing Example 3 Decryption Step 1 (Corrected) ---"
    );

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

    // Setup Structs for Decryption Call
    let shared_params = SharedParams { m, ring, p, q };
    // Manually construct the necessary parts of a PrivateKey-like structure for decrypt
    let decryption_secrets = DecryptionSecrets {
        b_inv: b_bar_inv, // Use the inverse of the Z_25 matrix
        a_inner,
        a_outer,
    };
    // Create a dummy PublicKey just to hold the shared params needed by decrypt's signature
    let dummy_public_key = PublicKey {
        shared: shared_params,
        // EncryptionParams are not needed for decryption, provide dummy values
        encryption_params: crypto::keypair::EncryptionParams {
            a: vec![],       // Not used
            b: vec![],       // Not used
            a_inner: vec![], // Not used
            a_outer: vec![], // Not used
        },
    };
    let private_key_stub = PrivateKey {
        public_key: dummy_public_key,
        decryption_secrets,
    };

    // Data from Example 3's First Encryption
    let original_message: Vector = vec![18, 0];
    let d: Vector = vec![2, 15];
    let d1: Vector = vec![16, 6]; // CORRECTED d1

    println!("Original Message (v): {:?}", original_message);
    println!("Using Corrected Ciphertext (d, d1): ({:?}, {:?})", d, d1);

    // --- Decryption using the corrected function ---
    let decrypted_block = decrypt(&private_key_stub, &d, &d1)?; // Use the stub
    println!("Decrypted Message Block: {:?}", decrypted_block);

    // --- Verification ---
    assert_eq!(
        decrypted_block, original_message,
        "Decrypted block does not match original message!"
    );

    println!(
        "
Example 3 Decryption Step Test (Corrected Logic & Ciphertext) Successful!"
    );

    Ok(())
}

#[test]
fn test_example_3_encryption_step() -> Result<(), CryptoError> {
    println!(
        "
--- Testing Example 3 Encryption Step (Corrected Logic) ---"
    );

    // --- Parameters from Example 3 ---
    let m = 25u64;
    let _p = 2usize; // Block size
    let _q = 4usize; // Variables
    let ring = Ring::try_with(m)?;

    // --- Alice's Secret Parameters (Publicly known parts for Bob's L construction) ---
    // These define the structure L(x) = B*(Ax + a_inner) + a_outer
    let b_matrix: Matrix = vec![vec![2, 1], vec![24, 24]]; // B from Example 3, in Z_25
    let a_inner: Vector = vec![1, 2];
    let a_outer: Vector = vec![7, 19];

    // --- Bob's Public Parameters (Matrix A from l(x)) ---
    let a_matrix: Matrix = vec![vec![5, 6, 9, 21], vec![0, 1, 11, 14]]; // A from l_hat in Example 3

    // --- Bob's Calculation Inputs ---
    let v: Vector = vec![18, 0]; // Original Message
    let a_rand: Vector = vec![0, 1, 0, 1]; // Random vector 'a' used in example

    // --- Manual Encryption Steps (Following Protocol from paper / test logic) ---

    // 1. Calculate d = A * a_rand
    let d = matrix_vector_mul(&a_matrix, &a_rand, &ring)?;
    let expected_d_from_example: Vector = vec![2, 15];
    println!("Calculated d = A * a_rand: {:?}", d);
    assert_eq!(
        d, expected_d_from_example,
        "Calculated d does not match example"
    );

    // 2. Calculate d1 = B * (v + d + a_inner) + a_outer
    // Note: The original test code directly used v+d. This seems to follow a simplified
    // encryption path from the test's comments rather than the full Ax=v step.
    // We replicate the test's calculation here.
    let v_plus_d = vector_add(&v, &d, &ring)?;
    let inner_term = vector_add(&v_plus_d, &a_inner, &ring)?;
    let b_mult = matrix_vector_mul(&b_matrix, &inner_term, &ring)?;
    let d1 = vector_add(&b_mult, &a_outer, &ring)?;

    // Expected d1 (Calculated manually based on the logic above)
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

    println!(
        "
Example 3 Encryption Step Test (Corrected Logic) Successful!"
    );

    Ok(())
}
