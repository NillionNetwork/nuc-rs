use crate::{
    did::Did,
    envelope::{NucAlgorithm, NucHeader, NucType},
};
use k256::ecdsa::{Signature, SigningKey};
use signature::Signer as _;
use std::ops::Deref;

/// A method for a DID that is derived from a secp256k1 key.
pub enum DidMethod {
    /// The modern `did:key` method.
    Key,
    /// The legacy `did:nil` method.
    #[deprecated(
        since = "0.2.0",
        note = "The `did:nil` method is legacy and will be removed in 0.3.0. Use `did:key` instead."
    )]
    Nil,
}

/// A signer that can be used to sign NUC tokens.
pub trait Signer {
    /// The DID of this signer.
    fn did(&self) -> &Did;

    /// The NUC header to use for tokens signed by this signer.
    fn header(&self) -> NucHeader;

    /// Sign a message.
    ///
    /// The message is the base64url-encoded header and payload, joined by a dot.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SigningError>;
}

/// An error that can occur when signing a NUC token.
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("signing failed: {0}")]
    SigningFailed(String),
}

/// A signer that uses a local `secp256k1` key.
pub struct Secp256k1Signer {
    key: SigningKey,
    did: Did,
    header: NucHeader,
}

impl Secp256k1Signer {
    /// Create a new `Secp256k1Signer`.
    #[allow(deprecated)]
    pub fn new(key: SigningKey, method: DidMethod) -> Self {
        let public_key: [u8; 33] = key.verifying_key().to_sec1_bytes().deref().try_into().unwrap();
        let (did, header) = match method {
            DidMethod::Key => (
                Did::key(public_key),
                NucHeader {
                    typ: Some(NucType::Nuc),
                    alg: NucAlgorithm::ES256K,
                    ver: Some("1.0.0".to_string()),
                    met: None,
                },
            ),
            DidMethod::Nil => {
                (Did::nil(public_key), NucHeader { typ: None, alg: NucAlgorithm::ES256K, ver: None, met: None })
            }
        };
        Self { key, did, header }
    }
}

impl Signer for Secp256k1Signer {
    fn did(&self) -> &Did {
        &self.did
    }

    fn header(&self) -> NucHeader {
        self.header.clone()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SigningError> {
        let signature: Signature =
            self.key.try_sign(message).map_err(|e| SigningError::SigningFailed(e.to_string()))?;
        Ok(signature.to_bytes().to_vec())
    }
}
