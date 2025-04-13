use sle_crypto::errors::SLECryptoError;
use sle_crypto::keypair::keys::{PrivateKey, PublicKey};
use sle_crypto::keypair::shared_params::SharedParams;

#[test]
fn happy_flow() -> Result<(), SLECryptoError> {
    let shared_params = SharedParams::try_with(7, 5, 2, 65, 12345, 5, 5)?;

    let private_key = PrivateKey::try_with(shared_params)?;
    let public_key = private_key.get_public_key()?;

    let cipher = private_key.shared_params.encrypt(&public_key, "Heh".to_string())?;

    let decoded_data = private_key.decrypt(cipher);

    dbg!(&decoded_data);

    Ok(())
}
