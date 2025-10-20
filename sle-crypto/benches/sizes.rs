use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, black_box};
use fake::faker::lorem::en::Words;
use fake::Fake;
use sle_crypto::keypair::{
    keys::{PrivateKey, PublicKey},
    shared_params::SharedParams,
};

fn setup_sle() -> (PrivateKey, PublicKey) {
    let shared_params = SharedParams::try_with(7, 5, 2, 65, 12345, 10, 15)
        .expect("Failed to create SLE SharedParams");
    let private_key = PrivateKey::try_with(shared_params).expect("Failed to create SLE PrivateKey");
    let public_key = private_key
        .get_public_key()
        .expect("Failed to get SLE PublicKey");
    (private_key, public_key)
}

fn make_string(len: usize) -> String {
    // Generate approximately len characters by repeating word sequences
    // This avoids allocating a single gigantic random string all at once
    let mut s = String::with_capacity(len);
    while s.len() < len {
        let words: Vec<String> = Words(10..20).fake();
        if !s.is_empty() { s.push(' '); }
        s.push_str(&words.join(" "));
        if s.len() > len {
            s.truncate(len);
        }
    }
    s
}

fn bench_sizes(c: &mut Criterion) {
    let (private_key, public_key) = setup_sle();

    let sizes: [(usize, &str); 3] = [
        (1_000, "1k"),
        (100_000, "100k"),
        (10_000_00, "1m"),
    ];

    let mut group = c.benchmark_group("SLE Sizes Encrypt/Decrypt");

    for (len, label) in sizes {
        let data = make_string(len);
        // precompute ciphertext for decrypt bench to avoid measuring encrypt twice
        let ciphertext = private_key
            .shared_params
            .encrypt(&public_key, data.clone())
            .expect("encrypt");

        group.bench_with_input(BenchmarkId::new("encrypt", label), &data, |b, d| {
            b.iter(|| {
                let _c = private_key
                    .shared_params
                    .encrypt(black_box(&public_key), black_box(d.clone()))
                    .expect("encrypt");
            });
        });

        group.bench_with_input(BenchmarkId::new("decrypt", label), &ciphertext, |b, ctext| {
            b.iter(|| {
                let _p = private_key.decrypt(black_box(ctext.clone())).expect("decrypt");
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_sizes);
criterion_main!(benches);


