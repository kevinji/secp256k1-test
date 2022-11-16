use secp256k1::{Message, Secp256k1, SecretKey};
use tiny_keccak::{Hasher, Keccak};

fn keccak256_hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    output
}

fn sign(private_key: &SecretKey, message: &[u8]) -> [u8; 64] {
    let hashed_message = keccak256_hash(message);
    let message = Message::from_slice(&hashed_message).unwrap();

    Secp256k1::signing_only()
        .sign_ecdsa(&message, private_key)
        .serialize_compact()
}

fn sign_recoverable(private_key: &SecretKey, message: &[u8]) -> [u8; 64] {
    let hashed_message = keccak256_hash(message);
    let message = Message::from_slice(&hashed_message).unwrap();

    let (_recovery, signature) = Secp256k1::signing_only()
        .sign_ecdsa_recoverable(&message, private_key)
        .serialize_compact();
    signature
}

#[cfg(test)]
mod tests {
    use super::{sign, sign_recoverable};
    use rand::RngCore;
    use secp256k1::SecretKey;

    #[test]
    fn same_sigs() {
        let mut rng = rand::thread_rng();
        let private_key = SecretKey::new(&mut rng);
        let mut message = [0u8; 64];
        rng.fill_bytes(&mut message);
        assert_eq!(
            sign(&private_key, &message),
            sign_recoverable(&private_key, &message)
        );
    }
}
