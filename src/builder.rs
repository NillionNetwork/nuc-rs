use crate::{
    did::Did,
    envelope::{NucTokenEnvelope, SignaturesValidated},
    policy::Policy,
    signer::{Signer, SigningError},
    token::{Command, JsonObject, NucToken, TokenBody},
};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::time::Duration;

// Helper to simplify unwrapping options in the builder
macro_rules! try_get {
    ($option:ident) => {
        $option.ok_or(NucTokenBuildError::MissingField(stringify!($option)))
    };
}

/// A Nuc token builder.
#[derive(Clone, Debug)]
pub struct NucTokenBuilder {
    body: TokenBody,
    audience: Option<Did>,
    subject: Option<Did>,
    not_before: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    command: Option<Command>,
    meta: Option<JsonObject>,
    nonce: Vec<u8>,
    proof: Option<NucTokenEnvelope<SignaturesValidated>>,
}

impl NucTokenBuilder {
    /// Construct a new builder.
    pub fn new(body: TokenBody) -> Self {
        Self {
            body,
            audience: Default::default(),
            subject: Default::default(),
            not_before: Default::default(),
            expires_at: Default::default(),
            command: Default::default(),
            meta: Default::default(),
            nonce: Default::default(),
            proof: Default::default(),
        }
    }

    /// Make this a delegation token using the given policy.
    pub fn delegation<I>(policies: I) -> Self
    where
        I: Into<Vec<Policy>>,
    {
        Self::new(TokenBody::Delegation(policies.into()))
    }

    /// Make this an invocation token using the given policy.
    pub fn invocation(args: JsonObject) -> Self {
        Self::new(TokenBody::Invocation(args))
    }

    /// Create a new builder using the given envelope as a base.
    ///
    /// This will pull as many parameters as it can from the given token, such as:
    ///
    /// * The subject.
    /// * The command.
    /// * Using it as a proof.
    pub fn extending(envelope: NucTokenEnvelope<SignaturesValidated>) -> Result<Self, ExtendTokenError> {
        let token = &envelope.token().token;
        if let TokenBody::Invocation(_) = &token.body {
            return Err(ExtendTokenError);
        }
        let output = Self::new(TokenBody::Delegation(vec![]))
            .command(token.command.clone())
            .subject(token.subject.clone())
            .proof(envelope);
        Ok(output)
    }

    /// Set the audience for this token.
    pub fn audience(mut self, did: Did) -> Self {
        self.audience = Some(did);
        self
    }

    /// Set the subject for this token.
    pub fn subject(mut self, did: Did) -> Self {
        self.subject = Some(did);
        self
    }

    /// Set the expiration time for this token.
    pub fn expires_at(mut self, timestamp: DateTime<Utc>) -> Self {
        self.expires_at = Some(timestamp);
        self
    }

    /// Set the expiration time for this token based on an offset from the current time.
    pub fn expires_in(mut self, offset: Duration) -> Self {
        self.expires_at = Some(Utc::now() + offset);
        self
    }

    /// Set the timestamp when this token first becomes valid for this token.
    pub fn not_before(mut self, timestamp: DateTime<Utc>) -> Self {
        self.not_before = Some(timestamp);
        self
    }

    /// Set the command for this token.
    pub fn command<T: Into<Command>>(mut self, command: T) -> Self {
        self.command = Some(command.into());
        self
    }

    /// Set the metadata for this token.
    pub fn meta(mut self, meta: JsonObject) -> Self {
        self.meta = Some(meta);
        self
    }

    /// Set the nonce for this token.
    pub fn nonce<T: Into<Vec<u8>>>(mut self, nonce: T) -> Self {
        self.nonce = nonce.into();
        self
    }

    /// Use the given envelope as a proof to be chained into the built token.
    pub fn proof(mut self, envelope: NucTokenEnvelope<SignaturesValidated>) -> Self {
        self.proof = Some(envelope);
        self
    }

    /// Set the body.
    pub fn body(mut self, body: TokenBody) -> Self {
        self.body = body;
        self
    }

    /// Build a Nuc token.
    pub async fn build(self, signer: &impl Signer) -> Result<String, NucTokenBuildError> {
        let Self { body, audience, subject, not_before, expires_at, command, meta, nonce, proof } = self;

        let audience = try_get!(audience)?;
        let subject = try_get!(subject)?;
        let command = try_get!(command)?;
        let issuer = signer.did().clone();

        let nonce = if nonce.is_empty() { rand::random::<[u8; 16]>().to_vec() } else { nonce };

        let mut token =
            NucToken { issuer, audience, subject, not_before, expires_at, command, body, meta, nonce, proofs: vec![] };

        let mut all_proofs = Vec::new();
        if let Some(envelope) = proof {
            let hash = envelope.token().compute_hash();
            let (root_proof, proofs) = envelope.into_parts();
            token.proofs.push(hash);
            all_proofs.push(root_proof);
            all_proofs.extend(proofs);
        }

        let (header, signature) = signer.sign_token(&token).await?;

        let header_b64 = to_base64_json(&header).map_err(|e| NucTokenBuildError::EncodingHeader(e.to_string()))?;
        let payload_b64 = to_base64_json(&token).map_err(|e| NucTokenBuildError::EncodingToken(e.to_string()))?;
        let signature_b64 = to_base64(&signature);

        let mut output = format!("{header_b64}.{payload_b64}.{signature_b64}");
        for proof in all_proofs {
            output.push('/');
            output.push_str(&proof.to_nuc_str());
        }
        Ok(output)
    }
}

/// An error when exending a token from another.
#[derive(Debug, thiserror::Error)]
#[error("invocations cannot be extended")]
pub struct ExtendTokenError;

/// An error when constructing a token.
#[derive(Debug, thiserror::Error)]
pub enum NucTokenBuildError {
    #[error("required field missing: {0}")]
    MissingField(&'static str),

    #[error("encoding header: {0}")]
    EncodingHeader(String),

    #[error("encoding token: {0}")]
    EncodingToken(String),

    #[error("signing failed: {0}")]
    Signing(#[from] SigningError),
}

pub(crate) fn to_base64<T: AsRef<[u8]>>(input: T) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(input)
}

pub(crate) fn to_base64_json<T: Serialize>(input: &T) -> Result<String, serde_json::Error> {
    let input = serde_json::to_vec(input)?;
    Ok(to_base64(&input))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::Eip712Signer;
    use crate::{
        Signer, Signer,
        did::Did,
        envelope::{NucTokenEnvelope, from_base64},
        keypair::Keypair,
        policy,
        signer::DidMethod,
    };
    use ethers::prelude::LocalWallet;
    use ethers::types::transaction::eip712::EIP712Domain;
    use serde::de::DeserializeOwned;
    use serde_json::json;
    use std::default::Default;
    use tokio;

    fn from_base64_json<T: DeserializeOwned>(input: &str) -> T {
        let input = from_base64(input).expect("invalid base 64");
        serde_json::from_slice(&input).expect("invalid JSON")
    }

    #[tokio::test]
    async fn minimal_token() {
        let keypair = Keypair::generate();
        let signer = keypair.signer(DidMethod::Key);
        NucTokenBuilder::delegation(vec![policy::op::eq(".foo", json!(42))])
            .audience(Did::key([0xbb; 33]))
            .subject(Did::key([0xcc; 33]))
            .command(["nil", "db", "read"])
            .build(&signer)
            .await
            .expect("build failed");
    }

    #[tokio::test]
    async fn extend_token() {
        let keypair = Keypair::generate();
        let signer = keypair.signer(DidMethod::Key);
        let base = NucTokenBuilder::delegation(vec![policy::op::eq(".foo", json!(42))])
            .audience(Did::key([0xbb; 33]))
            .subject(Did::key([0xcc; 33]))
            .command(["nil", "db", "read"])
            .build(&signer)
            .await
            .expect("build failed");
        let base = NucTokenEnvelope::decode(&base).expect("decode failed").validate_signatures().unwrap();

        let next = NucTokenBuilder::extending(base.clone())
            .expect("extending failed")
            .audience(Did::key([0xdd; 33]))
            .build(&signer)
            .await
            .expect("build failed");
        let next = NucTokenEnvelope::decode(&next).expect("decode failed").validate_signatures().unwrap();

        let (token, proofs) = next.into_parts();
        let token = token.token;
        assert_eq!(token.command, base.token().token.command);
        assert_eq!(token.subject, base.token().token.subject);
        assert_eq!(proofs.len(), 1);
        assert_eq!(proofs[0].token, base.token().token);
    }

    #[tokio::test]
    async fn encode_decode() {
        let keypair = Keypair::generate();
        let signer = keypair.signer(DidMethod::Key);
        let issuer_did = signer.did().clone();

        let token = NucTokenBuilder::delegation(vec![policy::op::eq(".foo", json!(42))])
            .audience(Did::key([0xbb; 33]))
            .subject(Did::key([0xcc; 33]))
            .command(["nil", "db", "read"])
            .not_before(DateTime::from_timestamp(1740494955, 0).unwrap())
            .expires_at(DateTime::from_timestamp(1740495955, 0).unwrap())
            .nonce([1, 2, 3])
            .meta(json!({"name": "bob"}).as_object().cloned().unwrap())
            .build(&signer)
            .await
            .expect("failed to build");

        let mut token_parts = token.split('.');
        let header = token_parts.next().expect("no header");
        let header = from_base64(header).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header).expect("invalid header");
        assert_eq!(header, json!({ "typ": "nuc", "alg": "ES256K", "ver": "1.0.0" }));

        let nuc = token_parts.next().expect("no token");
        let nuc: NucToken = from_base64_json(nuc);

        let expected = NucToken {
            issuer: issuer_did,
            audience: Did::key([0xbb; 33]),
            subject: Did::key([0xcc; 33]),
            not_before: Some(DateTime::from_timestamp(1740494955, 0).unwrap()),
            expires_at: Some(DateTime::from_timestamp(1740495955, 0).unwrap()),
            command: ["nil", "db", "read"].into(),
            body: TokenBody::Delegation(vec![policy::op::eq(".foo", json!(42))]),
            proofs: vec![],
            nonce: vec![1, 2, 3],
            meta: Some(json!({ "name": "bob" }).as_object().cloned().unwrap()),
        };
        assert_eq!(nuc, expected);
    }

    #[tokio::test]
    #[allow(deprecated)]
    async fn heterogeneous_chain() {
        // Setup - Define the actors in the delegation chain
        // Root authority (did:nil)
        let root_keypair = Keypair::generate();
        let root_signer = root_keypair.signer(DidMethod::Nil);

        // Intermediate authority (did:ethr)
        let eth_wallet = LocalWallet::new(&mut rand::thread_rng());
        let domain = EIP712Domain { name: Some("NUC".into()), version: Some("1.0.0".into()), ..Default::default() };
        let ethr_signer = Eip712Signer::new(domain, eth_wallet.clone());

        // Final actor (did:key)
        let final_keypair = Keypair::generate();
        let final_signer = final_keypair.signer(DidMethod::Key);

        // Step 1 - Root grants authority to the `ethr` identity.
        let root_delegation = NucTokenBuilder::delegation(vec![])
            .audience(Did::key([0xaa; 33]))
            .subject(ethr_signer.did().clone())
            .command(["nil", "db"])
            .build(&root_signer)
            .await
            .expect("building root nuc failed");

        let root_envelope = NucTokenEnvelope::decode(&root_delegation)
            .expect("decoding root failed")
            .validate_signatures()
            .expect("root validation failed");

        // Step 2: `ethr` identity delegates its authority to the `final` identity
        let ethr_delegation = NucTokenBuilder::extending(root_envelope.clone())
            .expect("extending from root failed")
            .audience(Did::key([0xaa; 33])) // Same resource server
            .subject(final_signer.did().clone()) // Delegate to final_signer
            .build(&ethr_signer)
            .await
            .expect("building ethr delegation failed");

        let ethr_envelope = NucTokenEnvelope::decode(&ethr_delegation)
            .expect("decoding ethr delegation failed")
            .validate_signatures()
            .expect("ethr delegation validation failed");

        // Step 3: Final actor invokes a command
        let final_invocation = NucTokenBuilder::invocation(json!({}).as_object().cloned().unwrap())
            .proof(ethr_envelope.clone())
            .audience(Did::key([0xaa; 33]))
            .subject(final_signer.did().clone())
            .command(["nil", "db", "read"])
            .build(&final_signer)
            .await
            .expect("building final invocation failed");

        let final_envelope = NucTokenEnvelope::decode(&final_invocation)
            .expect("decoding final invocation failed")
            .validate_signatures()
            .expect("final chain validation failed");

        assert_eq!(final_envelope.proofs().len(), 2, "invocation envelope should have two proofs");
    }
}
