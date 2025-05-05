use criterion::{Criterion, black_box, criterion_group, criterion_main};
use sle_crypto::keypair::keys::PrivateKey;
use sle_crypto::keypair::shared_params::SharedParams;

fn bench_happy_flow(c: &mut Criterion) {
    // 1) one‐time setup
    let shared_params =
        SharedParams::try_with(7, 5, 2, 65, 12345, 20, 20).expect("build shared params");
    let private_key = PrivateKey::try_with(shared_params.clone()).expect("make private key");
    let public_key = private_key.get_public_key().expect("extract public key");

    // the same message every iteration
    let original_data = "Heh safasdkjfhkjas fha sdf asda".to_string();

    c.bench_function("happy_flow", |b| {
        b.iter(|| {
            // 2) encrypt
            let cipher = private_key
                .shared_params
                .encrypt(&public_key, original_data.clone())
                .expect("encrypt");

            // 3) decrypt
            let decoded = private_key.decrypt(cipher).expect("decrypt");

            // 4) black_box the result so the optimizer can't drop it
            black_box(decoded.trim_end_matches('\0').to_string());
        })
    });
}

criterion_group!(benches, bench_happy_flow);
criterion_main!(benches);
