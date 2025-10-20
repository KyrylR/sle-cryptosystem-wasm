use sle_crypto::errors::SLECryptoError;
use sle_crypto::keypair::keys::PrivateKey;
use sle_crypto::keypair::shared_params::SharedParams;

use std::sync::Once;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

static INIT: Once = Once::new();

fn init_tracing() {
    INIT.call_once(|| {
        let env_filter = EnvFilter::try_from_default_env()
            .or_else(|_| EnvFilter::try_new("info"))
            .unwrap();
        let fmt_layer = fmt::layer()
            .with_target(true)
            .with_line_number(false)
            .with_file(false);

        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .init();
    });
}

#[test]
fn showcase_cipher_decipher_ukrainian_text() -> Result<(), SLECryptoError> {
    init_tracing();

    let shared_params = SharedParams::try_with(7, 5, 2, 65, 12345, 10, 15)?;
    let private_key = PrivateKey::try_with(shared_params.clone())?;
    let public_key = private_key.get_public_key()?;

    let original = "Вітання від крипто системи 1 учасникам семінару на його першому засіданні".to_string();

    let cipher = private_key
        .shared_params
        .encrypt(&public_key, original.clone())?;

    dbg!(&cipher);

    let decoded = private_key.decrypt(cipher)?;

    dbg!(&original, decoded.trim_end_matches('\0'));
    assert_eq!(original, decoded.trim_end_matches('\0'));

    Ok(())
}


