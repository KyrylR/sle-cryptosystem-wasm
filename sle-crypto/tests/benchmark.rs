use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, AeadCore, KeyInit, OsRng as AesOsRng},
};
use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::OsRng as ChaChaOsRng,
};
use criterion::{Bencher, Criterion, black_box, criterion_group, criterion_main};
use rand::RngCore;
use sle_crypto::keypair::{
    keys::{PrivateKey, PublicKey},
    shared_params::SharedParams,
};

const DATA_SIZE_BYTES: usize = 1024;

fn generate_data(size: usize) -> Vec<u8> {
    let mut data = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut data);
    data
}

fn setup_sle() -> (PrivateKey, PublicKey, String) {
    let shared_params = SharedParams::try_with(7, 5, 2, 65, 12345, 10, 15)
        .expect("Failed to create SLE SharedParams");
    let private_key = PrivateKey::try_with(shared_params).expect("Failed to create SLE PrivateKey");
    let public_key = private_key
        .get_public_key()
        .expect("Failed to get SLE PublicKey");

    let data_bytes = generate_data(DATA_SIZE_BYTES);
    let data_string = String::from_utf8_lossy(&data_bytes).to_string();

    (private_key, public_key, data_string)
}

fn bench_sle_encrypt(b: &mut Bencher) {
    let (private_key, public_key, data) = setup_sle();

    b.iter(|| {
        let _ciphertext = private_key
            .shared_params
            .encrypt(black_box(&public_key), black_box(data.clone()))
            .expect("SLE encryption failed");
    });
}

fn bench_sle_decrypt(b: &mut Bencher) {
    let (private_key, public_key, data) = setup_sle();

    let ciphertext = private_key
        .shared_params
        .encrypt(&public_key, data.clone())
        .expect("SLE encryption failed during setup");

    b.iter(|| {
        let _plaintext = private_key
            .decrypt(black_box(ciphertext.clone()))
            .expect("SLE decryption failed");
    });
}

fn setup_aes() -> (Aes256Gcm, Vec<u8>) {
    let key_bytes = Aes256Gcm::generate_key(AesOsRng);
    let cipher = Aes256Gcm::new(&key_bytes);
    let data = generate_data(DATA_SIZE_BYTES);
    (cipher, data)
}

fn bench_aes_encrypt(b: &mut Bencher) {
    let (cipher, data) = setup_aes();

    b.iter(|| {
        let nonce = Aes256Gcm::generate_nonce(&mut AesOsRng);

        let _ciphertext = cipher
            .encrypt(black_box(&nonce), black_box(data.as_slice()))
            .expect("AES encryption failed");
    });
}

fn bench_aes_decrypt(b: &mut Bencher) {
    let (cipher, data) = setup_aes();

    let nonce = Aes256Gcm::generate_nonce(&mut AesOsRng);
    let ciphertext = cipher
        .encrypt(&nonce, data.as_slice())
        .expect("AES encryption failed during setup");

    b.iter(|| {
        let _plaintext = cipher
            .decrypt(black_box(&nonce), black_box(ciphertext.as_slice()))
            .expect("AES decryption failed");

        assert_eq!(_plaintext, data);
    });
}

// --- ChaCha20Poly1305 Benchmark Functions ---

fn setup_chacha() -> (ChaCha20Poly1305, Vec<u8>) {
    let key_bytes = ChaCha20Poly1305::generate_key(&mut ChaChaOsRng);
    let cipher = ChaCha20Poly1305::new(&key_bytes);
    let data = generate_data(DATA_SIZE_BYTES);
    (cipher, data)
}

fn bench_chacha_encrypt(b: &mut Bencher) {
    let (cipher, data) = setup_chacha();
    b.iter(|| {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut ChaChaOsRng);
        let _ciphertext = cipher
            .encrypt(black_box(&nonce), black_box(data.as_slice()))
            .expect("ChaCha20Poly1305 encryption failed");
    });
}

fn bench_chacha_decrypt(b: &mut Bencher) {
    let (cipher, data) = setup_chacha();
    let nonce = ChaCha20Poly1305::generate_nonce(&mut ChaChaOsRng);
    let ciphertext = cipher
        .encrypt(&nonce, data.as_slice())
        .expect("ChaCha20Poly1305 encryption failed during setup");

    b.iter(|| {
        let _plaintext = cipher
            .decrypt(black_box(&nonce), black_box(ciphertext.as_slice()))
            .expect("ChaCha20Poly1305 decryption failed");
        assert_eq!(_plaintext, data);
    });
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Crypto Comparison");

    group.bench_function("SLE Encrypt", bench_sle_encrypt);
    group.bench_function("SLE Decrypt", bench_sle_decrypt);

    group.bench_function("AES-256-GCM Encrypt", bench_aes_encrypt);
    group.bench_function("AES-256-GCM Decrypt", bench_aes_decrypt);
    
    group.bench_function("ChaCha20Poly1305 Encrypt", bench_chacha_encrypt);
    group.bench_function("ChaCha20Poly1305 Decrypt", bench_chacha_decrypt);

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
