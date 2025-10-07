use crate::{
    did::Did,
    token::{
        NucToken, ProofHash,
        eip712::{Eip712DelegationPayload, Eip712InvocationPayload},
    },
};
use base64::{Engine, display::Base64Display, prelude::BASE64_URL_SAFE_NO_PAD};
use core::fmt;
use ethers::types::transaction::eip712::{EIP712Domain, Eip712, TypedData, Types};
use ethers::types::{H256, Signature as EthersSignature};
use k256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signature::Verifier;
use std::{collections::BTreeMap, iter, marker::PhantomData};

const DEFAULT_MAX_RAW_TOKEN_SIZE: usize = 1024 * 10;

/// An envelope for a Nuc token.
///
/// This contains the Nuc token itself along with all of its proofs.
#[derive(Clone, Debug)]
pub struct NucTokenEnvelope<T = SignaturesUnvalidated> {
    pub(crate) token: DecodedNucToken,
    pub(crate) proofs: Vec<DecodedNucToken>,
    pub(crate) _unused: PhantomData<T>,
}

impl NucTokenEnvelope<SignaturesUnvalidated> {
    /// Decode a Nuc token.
    ///
    /// This performs no integrity checks, and instead only ensures the token and its proofs are well formed.
    pub fn decode(s: &str) -> Result<Self, NucEnvelopeParseError> {
        NucEnvelopeDecoder::default().decode(s)
    }

    /// Encode this envelope.
    pub fn encode(&self) -> String {
        let tokens = iter::once(&self.token).chain(&self.proofs);
        let mut output = String::new();
        for (index, token) in tokens.enumerate() {
            if index > 0 {
                output.push('/');
            }
            output.push_str(&token.to_nuc_str());
        }
        output
    }

    /// Validate the signature of this token and all of its proofs.
    pub fn validate_signatures(self) -> Result<NucTokenEnvelope<SignaturesValidated>, InvalidSignature> {
        let tokens = iter::once(&self.token).chain(self.proofs.iter());
        for token in tokens {
            token.validate_signature()?;
        }
        Ok(NucTokenEnvelope { token: self.token, proofs: self.proofs, _unused: PhantomData })
    }
}

impl<T> NucTokenEnvelope<T> {
    /// Split this envelope into its parts.
    pub fn into_parts(self) -> (DecodedNucToken, Vec<DecodedNucToken>) {
        (self.token, self.proofs)
    }

    /// Get the token in this envelope.
    pub fn token(&self) -> &DecodedNucToken {
        &self.token
    }

    /// Get the proofs in this envelope.
    pub fn proofs(&self) -> &[DecodedNucToken] {
        &self.proofs
    }
}

/// A Nuc token envelope decoder.
#[derive(Debug)]
pub struct NucEnvelopeDecoder {
    /// The maximum raw token size, in bytes.
    pub max_raw_token_size: usize,
}

impl Default for NucEnvelopeDecoder {
    fn default() -> Self {
        Self { max_raw_token_size: DEFAULT_MAX_RAW_TOKEN_SIZE }
    }
}

impl NucEnvelopeDecoder {
    /// Decode a Nuc.
    pub fn decode(&self, s: &str) -> Result<NucTokenEnvelope, NucEnvelopeParseError> {
        if s.len() > self.max_raw_token_size {
            return Err(NucEnvelopeParseError::NucTooLarge(self.max_raw_token_size));
        }
        let mut nucs = s.split('/');

        // The first element is the actual token, the rest of them are its proofs
        let token_nuc_str = nucs.next().ok_or(NucEnvelopeParseError::NoInput)?;
        let token = DecodedNucToken::from_nuc_str(token_nuc_str)?;
        let mut proofs = Vec::new();
        for nuc_str in nucs {
            let proof = DecodedNucToken::from_nuc_str(nuc_str)?;
            proofs.push(proof);
        }
        Ok(NucTokenEnvelope { token, proofs, _unused: PhantomData })
    }
}

/// A tag type to indicate an envelope has had its signatures validated.
#[derive(Clone, Debug)]
pub struct SignaturesValidated;

/// A tag type to indicate an envelope has not had its signatures validated.
#[derive(Clone, Debug)]
pub struct SignaturesUnvalidated;

impl NucTokenEnvelope<SignaturesValidated> {
    /// Convert a validated envelope to an unvalidated one.
    pub fn unvalidate(self) -> NucTokenEnvelope<SignaturesUnvalidated> {
        NucTokenEnvelope { token: self.token, proofs: self.proofs, _unused: PhantomData }
    }
}

/// An error when parsing a Nuc envelope.
#[derive(Debug, thiserror::Error)]
pub enum NucEnvelopeParseError {
    #[error("empty input")]
    NoInput,

    #[error("NUC is larger than max allowed: {0} bytes")]
    NucTooLarge(usize),

    #[error("invalid NUC: {0}")]
    Nuc(#[from] NucParseError),
}

/// A raw Nuc token.
///
/// This contains the raw parts that were serialized from a Nuc and is used to have access to the
/// original unmodified
#[derive(Clone, Debug)]
pub struct RawNuc {
    pub(crate) header: Vec<u8>,
    pub(crate) payload: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}

impl RawNuc {
    fn from_nuc_str(s: &str) -> Result<Self, NucParseError> {
        let mut chunks = s.splitn(3, '.');
        let header = Self::parse_base64_next(&mut chunks, "header")?;
        let payload = Self::parse_base64_next(&mut chunks, "payload")?;
        let signature = chunks.next().ok_or(NucParseError::MissingComponent("signature"))?;
        let signature: Vec<u8> = from_base64(signature).map_err(|e| NucParseError::Base64("signature", e))?;
        Ok(Self { header, payload, signature })
    }

    fn to_nuc_str(&self) -> String {
        let header = Base64Display::new(&self.header, &BASE64_URL_SAFE_NO_PAD);
        let payload = Base64Display::new(&self.payload, &BASE64_URL_SAFE_NO_PAD);
        let signature = Base64Display::new(&self.signature, &BASE64_URL_SAFE_NO_PAD);
        format!("{header}.{payload}.{signature}")
    }

    fn parse_base64_next<'a, I>(iter: &mut I, component: &'static str) -> Result<Vec<u8>, NucParseError>
    where
        I: Iterator<Item = &'a str>,
    {
        let next = iter.next().ok_or(NucParseError::MissingComponent(component))?;
        from_base64(next).map_err(|e| NucParseError::Base64(component, e))
    }
}

/// An error when parsing a Nuc.
#[derive(Debug, thiserror::Error)]
pub enum NucParseError {
    #[error("no {0} component in nuc")]
    MissingComponent(&'static str),

    #[error("invalid base64 found on {0}: {1}")]
    Base64(&'static str, base64::DecodeError),

    #[error("invalid JSON on {0}: {1}")]
    Json(&'static str, serde_json::Error),
}

/// A decoded Nuc token.
///
/// This is a wrapper over a Nuc token along with its raw pieces to be able to re-serialize it
/// later on without altering its contents.
#[derive(Clone, Debug)]
pub struct DecodedNucToken {
    pub(crate) raw: RawNuc,
    pub(crate) token: NucToken,
}

impl DecodedNucToken {
    pub(crate) fn from_raw(raw: RawNuc) -> Result<Self, NucParseError> {
        // Validate the NUC header
        let _header: NucHeader = serde_json::from_slice(&raw.header).map_err(|e| NucParseError::Json("header", e))?;
        let token = serde_json::from_slice(&raw.payload).map_err(|e| NucParseError::Json("token", e))?;
        Ok(Self { raw, token })
    }

    fn from_nuc_str(s: &str) -> Result<Self, NucParseError> {
        let raw = RawNuc::from_nuc_str(s)?;
        Self::from_raw(raw)
    }

    pub(crate) fn to_nuc_str(&self) -> String {
        self.raw.to_nuc_str()
    }

    /// Compute this token's hash.
    pub fn compute_hash(&self) -> ProofHash {
        let input = self.to_nuc_str();
        let hash = Sha256::digest(&input);
        ProofHash(hash.into())
    }

    /// Validate the signature in this token.
    ///
    /// This validates the signature for this single token only and does not
    /// validate any proofs in the chain.
    pub(crate) fn validate_signature(&self) -> Result<(), InvalidSignature> {
        let header: NucHeader =
            serde_json::from_slice(&self.raw.header).map_err(|_| InvalidSignature::InvalidHeader)?;
        match header.typ {
            // This is a did:ethr token.
            Some(NucType::NucEip712) => {
                // The validation logic uses the domain and types from the token header itself
                let metadata: Eip712HeaderMetadata =
                    serde_json::from_value(header.meta.ok_or(InvalidSignature::InvalidHeader)?)
                        .map_err(|_| InvalidSignature::InvalidHeader)?;

                let Eip712HeaderMetadata { domain, primary_type, types } = metadata;

                let hash = match primary_type {
                    Eip712NucPayloadType::NucDelegationPayload => {
                        let payload = Eip712DelegationPayload::from(self.token.clone());
                        let message: BTreeMap<String, serde_json::Value> = serde_json::to_value(&payload)
                            .and_then(serde_json::from_value)
                            .map_err(|_| InvalidSignature::Eip712Encoding)?;
                        TypedData { domain, types, primary_type: "NucDelegationPayload".to_string(), message }
                            .encode_eip712()
                            .map(H256::from)
                    }
                    Eip712NucPayloadType::NucInvocationPayload => {
                        let payload = Eip712InvocationPayload::from(self.token.clone());
                        let message: BTreeMap<String, serde_json::Value> = serde_json::to_value(&payload)
                            .and_then(serde_json::from_value)
                            .map_err(|_| InvalidSignature::Eip712Encoding)?;
                        TypedData { domain, types, primary_type: "NucInvocationPayload".to_string(), message }
                            .encode_eip712()
                            .map(H256::from)
                    }
                }
                .map_err(|_| InvalidSignature::Eip712Encoding)?;

                let signature = EthersSignature::try_from(self.raw.signature.as_slice())
                    .map_err(|_| InvalidSignature::Signature)?;

                let recovered_address = signature.recover(hash).map_err(|_| InvalidSignature::Eip712Recovery)?;

                let Did::Ethr { address } = self.token.issuer else {
                    return Err(InvalidSignature::DidMethodMismatch);
                };

                if recovered_address.as_bytes() != address {
                    return Err(InvalidSignature::SignerAddressMismatch);
                }
            }
            // This is a did:key token.
            Some(NucType::Nuc) => {
                let Did::Key { public_key } = self.token.issuer else {
                    return Err(InvalidSignature::DidMethodMismatch);
                };
                self.verify_secp256k1_signature(&public_key)?;
            }
            // This is a legacy did:nil token.
            #[allow(deprecated)]
            None => {
                let Did::Nil { public_key } = self.token.issuer else {
                    return Err(InvalidSignature::DidMethodMismatch);
                };
                self.verify_secp256k1_signature(&public_key)?;
            }
        }
        Ok(())
    }

    fn verify_secp256k1_signature(&self, public_key: &[u8; 33]) -> Result<(), InvalidSignature> {
        let header = Base64Display::new(&self.raw.header, &BASE64_URL_SAFE_NO_PAD);
        let payload = Base64Display::new(&self.raw.payload, &BASE64_URL_SAFE_NO_PAD);
        let input = format!("{header}.{payload}");

        let verifying_key = VerifyingKey::from_sec1_bytes(public_key).map_err(|_| InvalidSignature::IssuerPublicKey)?;
        let k256_signature =
            Signature::try_from(self.raw.signature.as_slice()).map_err(|_| InvalidSignature::Signature)?;
        verifying_key.verify(input.as_bytes(), &k256_signature).map_err(|_| InvalidSignature::Signature)?;
        Ok(())
    }

    /// Get the Nuc token.
    pub fn token(&self) -> &NucToken {
        &self.token
    }

    /// Consume and return the inner token.
    pub fn into_token(self) -> NucToken {
        self.token
    }
}

/// An error during the verification of a token signature.
#[derive(Debug, thiserror::Error)]
pub enum InvalidSignature {
    #[error("invalid nuc header")]
    InvalidHeader,

    #[error("the did method does not match the nuc type")]
    DidMethodMismatch,

    #[error("Eip-712 encoding failed")]
    Eip712Encoding,

    #[error("Eip-712 recovery failed")]
    Eip712Recovery,

    #[error("signer address does not match issuer")]
    SignerAddressMismatch,

    #[error("invalid issuer public key")]
    IssuerPublicKey,

    #[error("invalid signature")]
    Signature,
}

/// The primary type for an Eip-712 Nuc payload signature.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum Eip712NucPayloadType {
    NucDelegationPayload,
    NucInvocationPayload,
}

impl fmt::Display for Eip712NucPayloadType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Eip712NucPayloadType::NucDelegationPayload => write!(f, "NucDelegationPayload"),
            Eip712NucPayloadType::NucInvocationPayload => write!(f, "NucInvocationPayload"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Eip712HeaderMetadata {
    pub domain: EIP712Domain,
    pub primary_type: Eip712NucPayloadType,
    pub types: Types,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NucHeader {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<NucType>,
    pub alg: NucAlgorithm,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ver: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NucType {
    #[serde(rename = "nuc")]
    Nuc,
    #[serde(rename = "nuc+eip712")]
    NucEip712,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NucAlgorithm {
    ES256K,
}

pub(crate) fn from_base64(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    BASE64_URL_SAFE_NO_PAD.decode(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::DelegationBuilder;
    use crate::{Signer, builder::to_base64, did::Did, policy, signer::DidMethod};
    use rstest::rstest;
    use serde_json::json;

    #[tokio::test]
    async fn decoding() {
        let signer = Signer::generate(DidMethod::Key);
        let encoded = DelegationBuilder::new()
            .policy(policy::op::eq(".foo", json!(42)))
            .audience(Did::key([0xbb; 33]))
            .subject(Did::key([0xcc; 33]))
            .command(["nil", "db", "read"])
            .sign_and_serialize(&*signer)
            .await
            .expect("build failed");
        let envelope = NucTokenEnvelope::decode(&encoded).expect("decode failed");
        envelope.validate_signatures().expect("signature validation failed");
    }

    #[tokio::test]
    async fn invalid_signature() {
        let signer = Signer::generate(DidMethod::Key);
        let token = DelegationBuilder::new()
            .policy(policy::op::eq(".foo", json!(42)))
            .audience(Did::key([0xbb; 33]))
            .subject(Did::key([0xcc; 33]))
            .command(["nil", "db", "read"])
            .sign_and_serialize(&*signer)
            .await
            .expect("build failed");
        let (base, signature) = token.rsplit_once(".").unwrap();

        // Change every byte in the signature and make sure validation fails every time.
        let signature = from_base64(signature).unwrap();
        for index in 0..signature.len() {
            let mut signature = signature.clone();
            signature[index] = signature[index].wrapping_add(1);
            let signature = to_base64(&signature);
            let token = format!("{base}.{signature}");
            let envelope = NucTokenEnvelope::decode(&token).expect("decode failed");
            envelope.validate_signatures().expect_err("validation succeeded");
        }
    }

    #[rstest]
    #[case::dot(".")]
    #[case::malformed_bas64(".&&&")]
    #[case::malformed_json(".eyJmb28iOiJiYXIifQ")]
    #[case::invalid_json(".eyJmb28iOiJiYXIi")]
    #[case::emoji(".🚀")]
    #[case::b64_emoji(".8J-agA==")]
    fn invalid_suffixes(#[case] suffix: &str) {
        // A valid token string for testing invalid suffixes
        let valid_token = "eyJ0eXAiOiJudWMiLCJhbGciOiJFUzI1NksiLCJ2ZXIiOiIxLjAuMCJ9.eyJpc3MiOiJkaWQ6a2V5OnpRM3NoRjZaZVFtb0dwb1FqWlRSZnZqR0QyU3ZjVFYxWFR2RkpBVDV2R3hFUDd3TyIsImF1ZCI6ImRpZDprZXk6elEzc2hGNlpjUW1vR3BvUWpaVFJmdmpHRDJTdmNUVjFYVHYyRkpBVDV2R3hFUDd3TyIsInN1YiI6ImRpZDprZXk6elEzc2hGNlpjUW1vR3BvUWpaVFJmdmpHRDJTdmNUVjFYVHYyRkpBVDV2R3hFUDd3TyIsImNtZCI6Ii8iLCJwb2wiOltdLCJub25jZSI6IjAwIn0.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let input = format!("{valid_token}{suffix}");
        NucTokenEnvelope::decode(&input).expect_err("decode succeeded  when it should have failed");
    }

    #[tokio::test]
    async fn nuc_serde() {
        let signer = Signer::generate(DidMethod::Key);
        let encoded = DelegationBuilder::new()
            .audience(Did::key([0xbb; 33]))
            .subject(Did::key([0xcc; 33]))
            .command(["nil", "db", "read"])
            .sign_and_serialize(&*signer)
            .await
            .expect("build failed");

        let token = RawNuc::from_nuc_str(&encoded).expect("decoding failed");

        // Split the raw token in its base64 decoded chunks
        let mut chunks = encoded.split('.').map(from_base64).collect::<Result<Vec<_>, _>>().unwrap().into_iter();
        let header = chunks.next().unwrap();
        let payload = chunks.next().unwrap();
        let signature = chunks.next().unwrap();

        assert_eq!(header, token.header);
        assert_eq!(payload, token.payload);
        assert_eq!(signature, token.signature);

        // Serialize the individual pieces of the decoded token.
        let serialized_header = to_base64(&token.header);
        let serialized_payload = to_base64(&token.payload);
        let serialized_signature = to_base64(token.signature);

        // Reconstruct back the token from its serialized pieces.
        let reconstructed = format!("{serialized_header}.{serialized_payload}.{serialized_signature}",);

        // Ensure the reconstructed token is still valid, meaning anyone can verify the signature
        // for a proof in an envelope.
        NucTokenEnvelope::decode(&reconstructed)
            .expect("reconstruction failed")
            .validate_signatures()
            .expect("signature validation failed");
    }

    #[tokio::test]
    async fn deep_nesting() {
        let signer = Signer::generate(DidMethod::Key);
        let mut policy = policy::op::eq(".foo", json!(42));
        for _ in 0..128 {
            policy = policy::op::not(policy);
        }
        let encoded = DelegationBuilder::new()
            .policy(policy)
            .audience(Did::key([0xbb; 33]))
            .subject(Did::key([0xcc; 33]))
            .command(["nil", "db", "read"])
            .sign_and_serialize(&*signer)
            .await
            .expect("build failed");
        let err = NucTokenEnvelope::decode(&encoded).expect_err("decode succeeded");
        assert!(matches!(err, NucEnvelopeParseError::Nuc(NucParseError::Json(_, _))));
    }

    #[test]
    fn too_large() {
        let token = " ".repeat(DEFAULT_MAX_RAW_TOKEN_SIZE + 1);
        let err = NucTokenEnvelope::decode(&token).expect_err("decode succeeded");
        assert!(matches!(err, NucEnvelopeParseError::NucTooLarge(_)));
    }

    #[test]
    fn metamask_created_nuc() {
        let token = "eyJ0eXAiOiJudWMrZWlwNzEyIiwiYWxnIjoiRVMyNTZLIiwidmVyIjoiMS4wLjAiLCJtZXRhIjp7ImRvbWFpbiI6eyJuYW1lIjoiTlVDIiwidmVyc2lvbiI6IjEiLCJjaGFpbklkIjoxfSwicHJpbWFyeVR5cGUiOiJOdWNJbnZvY2F0aW9uUGF5bG9hZCIsInR5cGVzIjp7Ik51Y0ludm9jYXRpb25QYXlsb2FkIjpbeyJuYW1lIjoiaXNzIiwidHlwZSI6InN0cmluZyJ9LHsibmFtZSI6ImF1ZCIsInR5cGUiOiJzdHJpbmcifSx7Im5hbWUiOiJzdWIiLCJ0eXBlIjoic3RyaW5nIn0seyJuYW1lIjoiY21kIiwidHlwZSI6InN0cmluZyJ9LHsibmFtZSI6ImFyZ3MiLCJ0eXBlIjoic3RyaW5nIn0seyJuYW1lIjoibmJmIiwidHlwZSI6InVpbnQyNTYifSx7Im5hbWUiOiJleHAiLCJ0eXBlIjoidWludDI1NiJ9LHsibmFtZSI6Im5vbmNlIiwidHlwZSI6InN0cmluZyJ9LHsibmFtZSI6InByZiIsInR5cGUiOiJzdHJpbmdbXSJ9XX19fQ.eyJpc3MiOiJkaWQ6ZXRocjoweGRGYjc2RUQzNzg5ZkI5ZTRkNjc2YmU0YzA2MDgzOTVhNDczMzdDZDkiLCJhdWQiOiJkaWQ6a2V5OnpRM3Noa0FSTDVKQUVCYkxmOGNxUEtwazNzVUFmYUhzMkZhTXoyaWtKZ3VhNk1qR3ciLCJzdWIiOiJkaWQ6ZXRocjoweGRGYjc2RUQzNzg5ZkI5ZTRkNjc2YmU0YzA2MDgzOTVhNDczMzdDZDkiLCJjbWQiOiIvbmlsL2F1dGgvcGF5bWVudHMvdmFsaWRhdGUiLCJhcmdzIjp7fSwibm9uY2UiOiIwN2U1MTNiMzI0ODY4NWJhODQ4YmJlZDIxMTY3ZjVkMyIsInByZiI6W119.kvMXcYmv64DTzufC1OyLkb8XIwmfbM_Bwk_RJD-z6RVplV7-zOrOzWfl1f9BR6_TmCBtMErYqn1Bpkty5j5yQBs";
        NucTokenEnvelope::decode(token)
            .expect("failed to decode")
            .validate_signatures()
            .expect("failed to validate signature");
    }
}
