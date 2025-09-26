use crate::{
    did::Did,
    signer::{DidMethod, Secp256k1Signer},
};
use k256::{SecretKey, ecdsa::SigningKey};
use std::ops::Deref;

/// An abstraction over a secp256k1 key pair.
///
/// This struct provides a unified API for managing keys, creating DIDs,
/// and generating signers, simplifying the user experience and aligning
/// with the nuc-ts library's ergonomics.
#[derive(Clone)]
pub struct Keypair {
    signing_key: SigningKey,
}

impl Keypair {
    /// Generates a new, random `Keypair`.
    pub fn generate() -> Self {
        let secret_key = SecretKey::random(&mut rand::thread_rng());
        Self { signing_key: secret_key.into() }
    }

    /// Creates a `Keypair` from a 32-byte secret key.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let secret_key = SecretKey::from_slice(bytes).expect("invalid key length");
        Self { signing_key: secret_key.into() }
    }

    /// Returns the raw 33-byte compressed public key.
    pub fn public_key(&self) -> [u8; 33] {
        self.signing_key.verifying_key().to_sec1_bytes().deref().try_into().unwrap()
    }

    /// Creates a `Did` (Decentralized Identifier) from this keypair's public key.
    ///
    /// # Arguments
    ///
    /// * `method` - The DID method to use (`DidMethod::Key` or `DidMethod::Nil`).
    #[allow(deprecated)]
    pub fn to_did(&self, method: DidMethod) -> Did {
        match method {
            DidMethod::Key => Did::key(self.public_key()),
            DidMethod::Nil => Did::nil(self.public_key()),
        }
    }

    /// Creates a `Secp256k1Signer` from this keypair.
    ///
    /// # Arguments
    ///
    /// * `method` - The DID method the signer should use.
    pub fn signer(&self, method: DidMethod) -> Secp256k1Signer {
        Secp256k1Signer::new(self.signing_key.clone(), method)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::Signer;

    #[test]
    #[allow(deprecated)]
    fn keypair_generates_consistent_components() {
        let keypair = Keypair::generate();

        // Create components
        let did_key = keypair.to_did(DidMethod::Key);
        let did_nil = keypair.to_did(DidMethod::Nil);
        let signer_key = keypair.signer(DidMethod::Key);
        let signer_nil = keypair.signer(DidMethod::Nil);

        // Assert DIDs are correct
        assert_eq!(did_key.to_string(), signer_key.did().to_string());
        assert_eq!(did_nil.to_string(), signer_nil.did().to_string());

        // Assert public keys match
        match signer_key.did() {
            Did::Key { public_key } => assert_eq!(public_key, &keypair.public_key()),
            _ => panic!("Expected did:key"),
        }
    }
}
