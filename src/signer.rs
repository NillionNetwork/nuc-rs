use crate::{
    builder::to_base64_json,
    did::Did,
    envelope::{NucAlgorithm, NucHeader, NucType},
    token::{Eip712NucPayload, NucToken},
};
use async_trait::async_trait;
use ethers::signers::Signer as EthersSigner;
use ethers::types::transaction::eip712::EIP712Domain;
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
        note = "The `did:nil` method is legacy and will be removed the next major version. Use `did:key` instead."
    )]
    Nil,
}

/// A Nuc token signer.
#[async_trait]
pub trait Signer {
    /// The DID of this signer.
    fn did(&self) -> &Did;

    /// Create and sign a Nuc for the given token.
    ///
    /// Returns the Nuc header and the resulting signature.
    async fn sign_token(&self, token: &NucToken) -> Result<(NucHeader, Vec<u8>), SigningError>;
}

/// An error that can occur when signing a Nuc token.
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
    pub(crate) fn new(key: SigningKey, method: DidMethod) -> Self {
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

#[async_trait]
impl Signer for Secp256k1Signer {
    fn did(&self) -> &Did {
        &self.did
    }

    async fn sign_token(&self, token: &NucToken) -> Result<(NucHeader, Vec<u8>), SigningError> {
        let header = self.header.clone();
        let header_b64 = to_base64_json(&header).map_err(|e| SigningError::SigningFailed(e.to_string()))?;
        let payload_b64 = to_base64_json(token).map_err(|e| SigningError::SigningFailed(e.to_string()))?;

        let message_to_sign = format!("{header_b64}.{payload_b64}");
        let signature: Signature =
            self.key.try_sign(message_to_sign.as_bytes()).map_err(|e| SigningError::SigningFailed(e.to_string()))?;

        Ok((header, signature.to_bytes().to_vec()))
    }
}

/// A signer that uses an Eip-712 compatible wallet.
pub struct Eip712Signer<S: EthersSigner> {
    did: Did,
    header: NucHeader,
    signer: S,
}

impl<S: EthersSigner> Eip712Signer<S> {
    /// Create a new Eip-712 signer.
    pub fn new(domain: EIP712Domain, signer: S) -> Self {
        let address: [u8; 20] = signer.address().into();
        let did = Did::ethr(address);
        let header = NucHeader {
            typ: Some(NucType::NucEip712),
            alg: NucAlgorithm::ES256K,
            ver: Some("1.0.0".to_string()),
            met: Some(serde_json::to_value(&domain).unwrap()),
        };
        Self { did, header, signer }
    }
}

#[async_trait]
impl<S: EthersSigner + Send + Sync> Signer for Eip712Signer<S> {
    fn did(&self) -> &Did {
        &self.did
    }

    async fn sign_token(&self, token: &NucToken) -> Result<(NucHeader, Vec<u8>), SigningError> {
        let payload = Eip712NucPayload::from(token.clone());
        let domain = serde_json::from_value(self.header.met.clone().unwrap())
            .map_err(|e| SigningError::SigningFailed(e.to_string()))?;
        let typed_data = payload.to_typed_data(domain).map_err(SigningError::SigningFailed)?;

        let signature =
            self.signer.sign_typed_data(&typed_data).await.map_err(|e| SigningError::SigningFailed(e.to_string()))?;

        Ok((self.header.clone(), signature.to_vec()))
    }
}

#[cfg(test)]
mod eip712_tests {
    use super::*;
    use crate::{builder::NucTokenBuilder, envelope::NucTokenEnvelope};
    use ethers::signers::{LocalWallet, Signer as EthersSigner};

    #[tokio::test]
    async fn test_eip712_signer_round_trip() {
        let domain = EIP712Domain {
            name: Some("NUC".into()),
            version: Some("1".into()),
            chain_id: Some(1.into()),
            verifying_contract: None,
            salt: None,
        };

        let wallet = LocalWallet::new(&mut rand::thread_rng());
        let address: [u8; 20] = wallet.address().into();
        let signer = Eip712Signer::new(domain, wallet);

        let aud_did = Did::ethr(address);
        let sub_did = Did::ethr(address);

        let nuc_string = NucTokenBuilder::delegation(vec![])
            .audience(aud_did.clone())
            .subject(sub_did.clone())
            .command(&[] as &[&str])
            .build(&signer)
            .await
            .expect("failed to build nuc");

        let envelope = NucTokenEnvelope::decode(&nuc_string).expect("failed to decode nuc");

        // Validate the signature to complete the round trip test
        envelope.validate_signatures().expect("signature validation failed");
    }
}
