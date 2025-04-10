use crate::system::errors::CryptoError;
use crate::system::matrix_ops::Vector;
use crate::system::{decrypt, encrypt};
use crate::{PrivateKey, PublicKey};
use rand::{RngCore, rng};

// Constants for serialization/padding
const P_SIZE_BYTES: usize = std::mem::size_of::<u32>();
const I64_SIZE_BYTES: usize = std::mem::size_of::<i64>();

/// Encodes a byte slice into a vector of `Vector`s (blocks).
///
/// Each output vector will have length `p`. The input `bytes` length must be a multiple of `p`.
/// Each byte is converted to an `i64`. The modulus `m` must be `>= 256`.
///
/// # Errors
///
/// Returns `CryptoError::EncodingError` if `bytes.len()` is not divisible by `p`.
/// Returns `CryptoError::InvalidParameters` if `m < 256`.
///
/// # Example
///
/// ```
/// # use crypto::system::matrix_ops::Vector;
/// # use crypto::codec::bytes_to_vectors; // Assuming pub for test or use internal visibility trick
/// # use crypto::system::errors::CryptoError;
/// let bytes = vec![10, 20, 30, 40];
/// let p = 2;
/// let m = 256;
/// let expected: Vec<Vector> = vec![vec![10, 20], vec![30, 40]];
/// assert_eq!(bytes_to_vectors(&bytes, p, m).unwrap(), expected);
///
/// // Fails if length not multiple of p
/// let bytes_bad = vec![10, 20, 30];
/// assert!(bytes_to_vectors(&bytes_bad, p, m).is_err());
/// ```
pub fn bytes_to_vectors(bytes: &[u8], p: usize, m: u64) -> Result<Vec<Vector>, CryptoError> {
    if bytes.len() % p != 0 {
        return Err(CryptoError::EncodingError(
            "Input bytes length must be a multiple of block size p".to_string(),
        ));
    }
    if m <= 255 {
        return Err(CryptoError::InvalidParameters(
            "Modulus m must be >= 256 to safely encode bytes.".to_string(),
        ));
    }

    bytes
        .chunks(p)
        .map(|chunk| {
            let vec: Vector = chunk.iter().map(|&byte| byte as i64).collect();
            Ok(vec)
        })
        .collect()
}

/// Decodes a slice of `Vector`s back into a single byte vector.
///
/// Each `i64` value in the input vectors must be within the valid byte range `[0, 255]`.
///
/// # Errors
///
/// Returns `CryptoError::DecodingError` if any value is outside the `[0, 255]` range.
///
/// # Example
///
/// ```
/// # use crypto::system::matrix_ops::Vector;
/// # use crypto::codec::vectors_to_bytes; // Assuming pub for test or use internal visibility trick
/// # use crypto::system::errors::CryptoError;
/// let vectors: Vec<Vector> = vec![vec![10, 20], vec![30, 40]];
/// let expected = vec![10, 20, 30, 40];
/// assert_eq!(vectors_to_bytes(&vectors).unwrap(), expected);
///
/// // Fails if value out of range
/// let vectors_bad: Vec<Vector> = vec![vec![10, 256]];
/// assert!(vectors_to_bytes(&vectors_bad).is_err());
/// ```
pub fn vectors_to_bytes(vectors: &[Vector]) -> Result<Vec<u8>, CryptoError> {
    let mut bytes = Vec::new();
    for vec in vectors {
        for &val in vec {
            if !(0..=255).contains(&val) {
                return Err(CryptoError::DecodingError(format!(
                    "Decrypted value {} out of byte range",
                    val
                )));
            }
            bytes.push(val as u8);
        }
    }
    Ok(bytes)
}

/// Adds PKCS#7 padding to the data to make its length a multiple of `block_size`.
///
/// # Example
///
/// ```
/// # use crypto::codec::pad_pkcs7; // Assuming pub for test or use internal visibility trick
/// let mut data = vec![1, 2, 3, 4, 5];
/// let block_size = 8;
/// pad_pkcs7(&mut data, block_size);
/// // Expected padding length is 8 - 5 = 3. Padding value is 3.
/// assert_eq!(data, vec![1, 2, 3, 4, 5, 3, 3, 3]);
///
/// let mut data2 = vec![1, 2, 3, 4, 5, 6, 7, 8];
/// pad_pkcs7(&mut data2, block_size);
/// // Expected padding length is 8 - 8 = 8 (full block). Padding value is 8.
/// assert_eq!(data2, vec![1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8]);
/// ```
pub fn pad_pkcs7(data: &mut Vec<u8>, block_size: usize) {
    let padding_len = block_size - (data.len() % block_size);
    let padding_val = padding_len as u8;
    for _ in 0..padding_len {
        data.push(padding_val);
    }
}

/// Removes PKCS#7 padding from the data.
///
/// # Errors
///
/// Returns `CryptoError::DecodingError` if the padding is invalid (e.g., empty data,
/// incorrect padding value or bytes).
///
/// # Example
///
/// ```
/// # use crypto::codec::unpad_pkcs7;
/// # use crypto::system::errors::CryptoError;
/// let mut data = vec![1, 2, 3, 4, 5, 3, 3, 3];
/// unpad_pkcs7(&mut data).unwrap();
/// assert_eq!(data, vec![1, 2, 3, 4, 5]);
///
/// let mut data_full_block = vec![1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8];
/// unpad_pkcs7(&mut data_full_block).unwrap();
/// assert_eq!(data_full_block, vec![1, 2, 3, 4, 5, 6, 7, 8]);
/// ```
pub fn unpad_pkcs7(data: &mut Vec<u8>) -> Result<(), CryptoError> {
    if data.is_empty() {
        return Err(CryptoError::DecodingError(
            "Cannot unpad empty data".to_string(),
        ));
    }
    let padding_val = *data.last().unwrap() as usize;
    if padding_val == 0 || padding_val > data.len() {
        return Err(CryptoError::DecodingError(
            "Invalid PKCS#7 padding value".to_string(),
        ));
    }
    for &i in data.iter().skip(data.len() - padding_val) {
        if i as usize != padding_val {
            return Err(CryptoError::DecodingError(
                "Invalid PKCS#7 padding bytes".to_string(),
            ));
        }
    }
    data.truncate(data.len() - padding_val);
    Ok(())
}

/// Serializes encrypted blocks (pairs of `(d, d1)` vectors) into a byte vector.
///
/// The format is:
/// `[p_le_bytes | d0_val0_le_bytes | ... | d0_val(p-1)_le_bytes | d1_0_val0_le_bytes | ... | d1_0_val(p-1)_le_bytes | d1_val0_le_bytes | ... ]`
/// Where:
/// - `p_le_bytes`: The block size `p` as `u32` in little-endian (4 bytes).
/// - `val_le_bytes`: Each `i64` value in the vectors as little-endian bytes (8 bytes).
///
/// # Errors
///
/// Returns `CryptoError::SerializationError` if `p` is too large or if block sizes mismatch.
///
/// # Example
///
/// ```
/// # use crypto::system::matrix_ops::Vector;
/// # use crypto::codec::serialize_ciphertext; // Assuming pub for test or use internal visibility trick
/// # use crypto::system::errors::CryptoError;
/// let p: usize = 2;
/// let blocks: Vec<(Vector, Vector)> = vec![
///     (vec![1, 2], vec![3, 4]),
///     (vec![5, 6], vec![7, 8]),
/// ];
/// let p_bytes = (p as u32).to_le_bytes(); // [2, 0, 0, 0]
/// let val_bytes: Vec<u8> = vec![
///     1i64.to_le_bytes(), 2i64.to_le_bytes(), 3i64.to_le_bytes(), 4i64.to_le_bytes(), // Block 0
///     5i64.to_le_bytes(), 6i64.to_le_bytes(), 7i64.to_le_bytes(), 8i64.to_le_bytes(), // Block 1
/// ].into_iter().flatten().collect();
///
/// let mut expected = Vec::new();
/// expected.extend_from_slice(&p_bytes);
/// expected.extend_from_slice(&val_bytes);
///
/// assert_eq!(serialize_ciphertext(&blocks, p).unwrap(), expected);
/// ```
pub fn serialize_ciphertext(blocks: &[(Vector, Vector)], p: usize) -> Result<Vec<u8>, CryptoError> {
    if p > u32::MAX as usize {
        return Err(CryptoError::SerializationError(
            "Block size p too large for serialization format".to_string(),
        ));
    }
    let p_bytes = (p as u32).to_le_bytes();
    let mut result = Vec::with_capacity(P_SIZE_BYTES + blocks.len() * 2 * p * I64_SIZE_BYTES);
    result.extend_from_slice(&p_bytes);

    for (d, d1) in blocks {
        if d.len() != p || d1.len() != p {
            return Err(CryptoError::SerializationError(
                "Ciphertext block size mismatch".to_string(),
            ));
        }
        // Simple serialization: concatenate i64 values as little-endian bytes
        for &val in d {
            result.extend_from_slice(&val.to_le_bytes());
        }
        for &val in d1 {
            result.extend_from_slice(&val.to_le_bytes());
        }
    }
    Ok(result)
}

/// Deserializes bytes back into encrypted blocks (pairs of `(d, d1)` vectors).
///
/// Expects the format produced by `serialize_ciphertext`.
///
/// # Errors
///
/// Returns `CryptoError::DeserializationError` if the data is too short, `p` is zero,
/// the data length is inconsistent, or slicing fails.
///
/// # Example
///
/// ```
/// # use crypto::system::matrix_ops::Vector;
/// # use crypto::codec::{serialize_ciphertext, deserialize_ciphertext}; // Assuming pub for test or use internal visibility trick
/// # use crypto::system::errors::CryptoError;
/// let p: usize = 2;
/// let original_blocks: Vec<(Vector, Vector)> = vec![
///     (vec![1, 2], vec![3, 4]),
///     (vec![5, 6], vec![7, 8]),
/// ];
/// let serialized = serialize_ciphertext(&original_blocks, p).unwrap();
///
/// let deserialized_blocks = deserialize_ciphertext(&serialized).unwrap();
/// assert_eq!(deserialized_blocks, original_blocks);
///
/// // Fails on short data
/// let short_data = vec![0, 0]; // Less than 4 bytes for p
/// assert!(deserialize_ciphertext(&short_data).is_err());
///
/// // Fails on inconsistent length
/// let mut bad_data = serialized.clone();
/// bad_data.pop(); // Remove one byte
/// assert!(deserialize_ciphertext(&bad_data).is_err());
/// ```
pub fn deserialize_ciphertext(data: &[u8]) -> Result<Vec<(Vector, Vector)>, CryptoError> {
    if data.len() < P_SIZE_BYTES {
        return Err(CryptoError::DeserializationError(
            "Ciphertext too short to contain block size".to_string(),
        ));
    }

    let p_bytes = data[0..P_SIZE_BYTES].try_into().unwrap(); // Safe due to check above
    let p = u32::from_le_bytes(p_bytes) as usize;
    if p == 0 {
        return Err(CryptoError::DeserializationError(
            "Deserialized block size p cannot be zero".to_string(),
        ));
    }

    let block_data = &data[P_SIZE_BYTES..];
    let bytes_per_val = I64_SIZE_BYTES;
    let bytes_per_block_pair = 2 * p * bytes_per_val;

    if block_data.len() % bytes_per_block_pair != 0 {
        return Err(CryptoError::DeserializationError(
            "Ciphertext data length not multiple of block pair size".to_string(),
        ));
    }

    let num_blocks = block_data.len() / bytes_per_block_pair;
    let mut blocks = Vec::with_capacity(num_blocks);

    for i in 0..num_blocks {
        let start = i * bytes_per_block_pair;
        let end_d = start + p * bytes_per_val;
        let _end_d1 = end_d + p * bytes_per_val;

        let mut d = Vec::with_capacity(p);
        for j in 0..p {
            let val_start = start + j * bytes_per_val;
            let val_end = val_start + bytes_per_val;
            let val_bytes: [u8; I64_SIZE_BYTES] =
                block_data[val_start..val_end].try_into().map_err(|_| {
                    CryptoError::DeserializationError(
                        "Failed to slice i64 for d vector".to_string(),
                    )
                })?;
            d.push(i64::from_le_bytes(val_bytes));
        }

        let mut d1 = Vec::with_capacity(p);
        for j in 0..p {
            let val_start = end_d + j * bytes_per_val;
            let val_end = val_start + bytes_per_val;
            let val_bytes: [u8; I64_SIZE_BYTES] =
                block_data[val_start..val_end].try_into().map_err(|_| {
                    CryptoError::DeserializationError(
                        "Failed to slice i64 for d1 vector".to_string(),
                    )
                })?;
            d1.push(i64::from_le_bytes(val_bytes));
        }
        blocks.push((d, d1));
    }

    Ok(blocks)
}

/// Encrypts a string message using the provided public key.
///
/// The process involves:
/// 1. Padding the message bytes using PKCS#7 to ensure its length is a multiple of the block size `p`.
/// 2. Encoding the padded bytes into message vectors (blocks) of size `p`, with elements modulo `m`.
/// 3. Encrypting each message vector individually using the `encrypt` function, generating a unique seed for each block.
/// 4. Serializing the resulting ciphertext blocks (pairs of `(d, d1)` vectors) into a single byte vector.
///
/// # Arguments
///
/// * `key` - A reference to the `PublicKey`.
/// * `message` - The string slice to encrypt.
///
/// # Returns
///
/// A `Result` containing the ciphertext as a `Vec<u8>` on success, or a `CryptoError` on failure.
///
/// # Example
///
/// ```rust
/// use crypto::keypair::PrivateKey;
/// use crypto::codec::encrypt_string;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let m = 257; let p = 8; let q = 10; let seed = 12345u64;
/// let private_key = PrivateKey::generate(m, p, q, seed)?;
/// let public_key = private_key.public_key;
/// let message = "hello";
///
/// let ciphertext = encrypt_string(&public_key, message)?;
/// assert!(!ciphertext.is_empty());
/// // In a real scenario, you'd pass this ciphertext to decrypt_string
/// # Ok(())
/// # }
/// ```
pub fn encrypt_string(key: &PublicKey, message: &str) -> Result<Vec<u8>, CryptoError> {
    let p = key.shared.p;
    let m = key.shared.m;

    // 1. Convert string to bytes and pad
    let mut bytes = message.as_bytes().to_vec();
    pad_pkcs7(&mut bytes, p);

    // 2. Encode bytes into message vectors (blocks)
    let message_vectors = bytes_to_vectors(&bytes, p, m)?;

    // 3. Encrypt each block
    let mut encrypted_blocks = Vec::with_capacity(message_vectors.len());
    for v in message_vectors {
        // Generate a unique, secure seed for each block encryption
        let mut seed_bytes = [0u8; 8];
        rng().fill_bytes(&mut seed_bytes);
        let encrypt_seed = u64::from_le_bytes(seed_bytes);

        let ciphertext_block = encrypt(key, &v, encrypt_seed)?;
        encrypted_blocks.push(ciphertext_block);
    }

    // 4. Serialize the encrypted blocks
    serialize_ciphertext(&encrypted_blocks, p)
}

/// Decrypts a byte slice representing ciphertext using the provided private key.
///
/// The process involves:
/// 1. Deserializing the input byte slice into encrypted blocks (pairs of `(d, d1)` vectors).
/// 2. Decrypting each block individually using the `decrypt` function.
/// 3. Decoding the resulting plaintext vectors back into a single byte vector.
/// 4. Removing the PKCS#7 padding from the byte vector.
/// 5. Converting the unpadded bytes back into a UTF-8 string.
///
/// # Arguments
///
/// * `key` - A reference to the `PrivateKey`.
/// * `ciphertext` - The byte slice containing the serialized ciphertext.
///
/// # Returns
///
/// A `Result` containing the original `String` on success, or a `CryptoError` on failure (e.g., if the ciphertext is malformed, padding is invalid, or UTF-8 conversion fails).
///
/// # Example
///
/// ```rust
/// use crypto::keypair::PrivateKey;
/// use crypto::codec::{encrypt_string, decrypt_string};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let m = 257; let p = 8; let q = 10; let seed = 12345u64;
/// let private_key = PrivateKey::generate(m, p, q, seed)?;
/// let public_key = private_key.public_key.clone();
/// let original_message = "Secret message!";
///
/// // Encrypt first
/// let ciphertext = encrypt_string(&public_key, original_message)?;
///
/// // Now decrypt
/// let decrypted_message = decrypt_string(&private_key, &ciphertext)?;
///
/// assert_eq!(decrypted_message, original_message);
/// # Ok(())
/// # }
/// ```
pub fn decrypt_string(key: &PrivateKey, ciphertext: &[u8]) -> Result<String, CryptoError> {
    // 1. Deserialize the ciphertext bytes into blocks (d, d1)
    let encrypted_blocks = deserialize_ciphertext(ciphertext)?;

    // 2. Decrypt each block
    let mut decrypted_vectors = Vec::with_capacity(encrypted_blocks.len());
    for (d, d1) in encrypted_blocks {
        let decrypted_block = decrypt(key, &d, &d1)?;
        decrypted_vectors.push(decrypted_block);
    }

    // 3. Decode vectors back to bytes
    let mut bytes = vectors_to_bytes(&decrypted_vectors)?;

    // 4. Unpad bytes
    unpad_pkcs7(&mut bytes)?;

    // 5. Convert bytes back to string
    String::from_utf8(bytes)
        .map_err(|e| CryptoError::DecodingError(format!("UTF-8 conversion failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::PrivateKey;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let m = 257;
        let p = 8;
        let q = 10;
        let seed = 98765u64;
        let private_key = PrivateKey::generate(m, p, q, seed).unwrap();
        let public_key = private_key.public_key.clone();
        let original_message = "This is a secret message that needs encryption.";

        let ciphertext = encrypt_string(&public_key, original_message).unwrap();
        let decrypted_message = decrypt_string(&private_key, &ciphertext).unwrap();

        assert_eq!(decrypted_message, original_message);
    }

    #[test]
    fn encrypt_decrypt_empty_string() {
        let m = 257;
        let p = 8;
        let q = 10;
        let seed = 11223u64;
        let private_key = PrivateKey::generate(m, p, q, seed).unwrap();
        let public_key = private_key.public_key.clone();
        let original_message = "";

        let ciphertext = encrypt_string(&public_key, original_message).unwrap();
        // Empty string still gets padded to one block
        assert!(!ciphertext.is_empty());

        let decrypted_message = decrypt_string(&private_key, &ciphertext).unwrap();
        assert_eq!(decrypted_message, original_message);
    }

    #[test]
    fn test_padding_unpadding() {
        let block_size = 8;
        let mut data1 = vec![1, 2, 3];
        pad_pkcs7(&mut data1, block_size);
        assert_eq!(data1, vec![1, 2, 3, 5, 5, 5, 5, 5]);
        unpad_pkcs7(&mut data1).unwrap();
        assert_eq!(data1, vec![1, 2, 3]);

        let mut data2 = vec![1, 2, 3, 4, 5, 6, 7, 8];
        pad_pkcs7(&mut data2, block_size);
        assert_eq!(data2, vec![1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8]);
        unpad_pkcs7(&mut data2).unwrap();
        assert_eq!(data2, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_vector_byte_conversion() {
        let bytes = vec![10, 20, 30, 40, 50, 60];
        let p = 3;
        let m = 256;
        let vectors = bytes_to_vectors(&bytes, p, m).unwrap();
        assert_eq!(vectors, vec![vec![10, 20, 30], vec![40, 50, 60]]);
        let recovered_bytes = vectors_to_bytes(&vectors).unwrap();
        assert_eq!(recovered_bytes, bytes);
    }

    #[test]
    fn test_serialization_deserialization() {
        let p: usize = 4;
        let blocks: Vec<(Vector, Vector)> = vec![
            (vec![10, 20, 30, 40], vec![50, 60, 70, 80]),
            (vec![-1, -2, -3, -4], vec![-5, -6, -7, -8]), // Test negative numbers
        ];
        let serialized = serialize_ciphertext(&blocks, p).unwrap();
        let deserialized = deserialize_ciphertext(&serialized).unwrap();
        assert_eq!(deserialized, blocks);
    }

    #[test]
    fn test_decrypt_invalid_ciphertext() {
        let m = 257;
        let p = 8;
        let q = 10;
        let seed = 11111u64;
        let private_key = PrivateKey::generate(m, p, q, seed).unwrap();

        // 1. Ciphertext too short
        let short_ciphertext = vec![1, 2, 3];
        assert!(decrypt_string(&private_key, &short_ciphertext).is_err());

        // 2. Incorrect block size encoding (p=0)
        let mut bad_p_ciphertext = vec![0u8; P_SIZE_BYTES]; // p = 0
        bad_p_ciphertext.extend_from_slice(&vec![0; 2 * p * I64_SIZE_BYTES]); // Add dummy data
        assert!(decrypt_string(&private_key, &bad_p_ciphertext).is_err());

        // 3. Length not multiple of block pair size
        let good_ciphertext = encrypt_string(&private_key.public_key, "test").unwrap();
        let mut truncated_ciphertext = good_ciphertext.clone();
        truncated_ciphertext.pop(); // Make length invalid
        assert!(decrypt_string(&private_key, &truncated_ciphertext).is_err());

        // 4. Invalid padding (can be hard to trigger directly without crafting bad plaintext)
        // But we can test unpad directly
        let mut bad_padding_data = vec![1, 2, 3, 4, 5, 9, 9, 9]; // Padding val 9 > len 8
        assert!(unpad_pkcs7(&mut bad_padding_data).is_err());

        // 5. Invalid UTF-8 sequence after decryption and unpadding
        // Craft a ciphertext that decrypts to invalid UTF-8
        // This is complex, relies on internals. Assume padding is correct.
        let bad_utf8_bytes = vec![0x80]; // Invalid UTF-8 start byte
        let mut padded_bad_bytes = bad_utf8_bytes.clone();
        pad_pkcs7(&mut padded_bad_bytes, p);
        let bad_vectors = bytes_to_vectors(&padded_bad_bytes, p, m).unwrap();
        let mut bad_encrypted_blocks = Vec::new();
        for v in bad_vectors {
            let mut seed_bytes = [0u8; 8];
            rng().fill_bytes(&mut seed_bytes);
            let encrypt_seed = u64::from_le_bytes(seed_bytes);
            bad_encrypted_blocks.push(encrypt(&private_key.public_key, &v, encrypt_seed).unwrap());
        }
        let bad_utf8_ciphertext = serialize_ciphertext(&bad_encrypted_blocks, p).unwrap();
        match decrypt_string(&private_key, &bad_utf8_ciphertext) {
            Err(CryptoError::DecodingError(msg)) => {
                assert!(msg.contains("UTF-8 conversion failed"))
            }
            _ => panic!("Expected UTF-8 decoding error"),
        }
    }
}
