use crate::{
    did::Did,
    envelope::{DecodedNucToken, NucHeader, NucTokenEnvelope, RawNuc, SignaturesValidated},
    policy::Policy,
    signer::{Signer, SigningError},
    token::{Command, JsonObject, NucToken, TokenBody},
};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::time::Duration;

/// The generic base implementation for Nuc token builders.
///
/// This struct provides the base functionality for both delegation and invocation builders.
#[derive(Clone, Debug)]
pub struct NucBuilderBase<B> {
    /// Serialised to pol for a Nuc delegation or args for a Nuc invocation
    body: B,
    audience: Option<Did>,
    subject: Option<Did>,
    not_before: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    command: Option<Command>,
    meta: Option<JsonObject>,
    nonce: Vec<u8>,
    proofs: Vec<DecodedNucToken>,
}

/// A builder for constructing Nuc delegation tokens.
///
/// Delegation tokens grant authority to another party and can include policies
/// that constrain how that authority may be used.
///
/// # Example
///
/// ```no_run
/// # use nillion_nucs::builder::DelegationBuilder;
/// # use nillion_nucs::did::Did;
/// # async fn example(signer: &impl nillion_nucs::signer::Signer) {
/// let token = DelegationBuilder::new()
///     .audience(Did::key([0xaa; 33]))
///     .subject(Did::key([0xbb; 33]))
///     .command(["nil", "db", "read"])
///     .sign(signer)
///     .await
///     .unwrap();
/// # }
/// ```
pub type DelegationBuilder = NucBuilderBase<Vec<Policy>>;

/// A builder for constructing Nuc invocation tokens.
///
/// Invocation tokens execute a specific command with arguments,
/// consuming the authority granted by a delegation chain.
///
/// # Example
///
/// ```no_run
/// # use nillion_nucs::builder::InvocationBuilder;
/// # use nillion_nucs::did::Did;
/// # use serde_json::json;
/// # async fn example(signer: &impl nillion_nucs::signer::Signer) {
/// let token = InvocationBuilder::new()
///     .audience(Did::key([0xaa; 33]))
///     .subject(Did::key([0xbb; 33]))
///     .command(["nil", "db", "read"])
///     .arguments(json!({ "table": "users" }))
///     .sign(signer)
///     .await
///     .unwrap();
/// # }
/// ```
pub type InvocationBuilder = NucBuilderBase<serde_json::Value>;

impl<B> NucBuilderBase<B> {
    /// Sets the audience (resource server) that will validate this token.
    ///
    /// This field is required and must be set before signing.
    pub fn audience(mut self, did: Did) -> Self {
        self.audience = Some(did);
        self
    }

    /// Sets the subject (identity) that this token authorizes.
    ///
    /// This field is required and must be set before signing.
    pub fn subject(mut self, did: Did) -> Self {
        self.subject = Some(did);
        self
    }

    /// Sets the expiration time for this token.
    ///
    /// After this time, the token will no longer be valid.
    pub fn expires_at(mut self, timestamp: DateTime<Utc>) -> Self {
        self.expires_at = Some(timestamp);
        self
    }

    /// Sets the expiration time relative to the current time.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::time::Duration;
    /// # use nillion_nucs::builder::DelegationBuilder;
    /// let builder = DelegationBuilder::new()
    ///     .expires_in(Duration::from_secs(3600)); // Expires in 1 hour
    /// ```
    pub fn expires_in(mut self, offset: Duration) -> Self {
        self.expires_at = Some(Utc::now() + offset);
        self
    }

    /// Sets the time before which this token is not valid.
    ///
    /// The token cannot be used before this timestamp.
    pub fn not_before(mut self, timestamp: DateTime<Utc>) -> Self {
        self.not_before = Some(timestamp);
        self
    }

    /// Sets the command that this token authorizes.
    ///
    /// This field is required and must be set before signing.
    /// Commands are hierarchical, with more specific commands inheriting
    /// authority from their parent commands.
    pub fn command<T: Into<Command>>(mut self, command: T) -> Self {
        self.command = Some(command.into());
        self
    }

    /// Sets optional metadata for this token.
    ///
    /// Metadata provides additional context but does not affect authorization.
    pub fn meta(mut self, meta: JsonObject) -> Self {
        self.meta = Some(meta);
        self
    }

    /// Sets a custom nonce for this token.
    ///
    /// If not set, a random nonce will be generated during signing.
    /// The nonce ensures token uniqueness.
    pub fn nonce<T: Into<Vec<u8>>>(mut self, nonce: T) -> Self {
        self.nonce = nonce.into();
        self
    }

    /// Private helper method for building and signing a token.
    async fn build_and_sign_internal(
        self,
        signer: &impl Signer,
        token_body: TokenBody,
    ) -> Result<(NucToken, NucHeader, Vec<u8>, Vec<DecodedNucToken>), NucTokenBuildError> {
        // Destructure self to get ownership of all fields
        let NucBuilderBase {
            body: _, // body is passed in as token_body argument
            audience,
            subject,
            not_before,
            expires_at,
            command,
            meta,
            nonce,
            proofs,
        } = self;

        // Validate required fields
        let audience = audience.ok_or(NucTokenBuildError::MissingField("audience"))?;
        let subject = subject.ok_or(NucTokenBuildError::MissingField("subject"))?;
        let command = command.ok_or(NucTokenBuildError::MissingField("command"))?;

        // Generate nonce if not set
        let nonce = if nonce.is_empty() { rand::random::<[u8; 16]>().to_vec() } else { nonce };

        // A token can only have one proof, which is the head of the proof chain.
        let proof_hashes: Vec<_> = proofs.iter().take(1).map(|p| p.compute_hash()).collect();

        // Build the token
        let token = NucToken {
            issuer: *signer.did(),
            audience,
            subject,
            not_before,
            expires_at,
            command,
            body: token_body,
            meta,
            nonce,
            proofs: proof_hashes,
        };

        // Sign the token
        let (header, signature) = signer.sign_token(&token).await?;

        Ok((token, header, signature, proofs))
    }
}

impl Default for DelegationBuilder {
    fn default() -> Self {
        Self {
            body: vec![],
            audience: None,
            subject: None,
            not_before: None,
            expires_at: None,
            command: None,
            meta: None,
            nonce: vec![],
            proofs: vec![],
        }
    }
}

impl DelegationBuilder {
    /// Creates a new root delegation token builder.
    ///
    /// Use this when creating the first token in a delegation chain.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a chained delegation builder from a proof envelope.
    ///
    /// This method inherits the `subject` and `command` from the proof token,
    /// and carries forward the entire proof chain from the envelope.
    /// The proof must be a delegation; attempting to extend an invocation will return an error.
    ///
    /// # Errors
    ///
    /// Returns `NucTokenBuildError::CannotExtendInvocation` if the proof is an invocation.
    pub fn extending(proof: NucTokenEnvelope<SignaturesValidated>) -> Result<Self, NucTokenBuildError> {
        let (root_proof, proofs_chain) = proof.into_parts();
        let token = root_proof.token.clone();

        // Cannot extend from an invocation
        if let TokenBody::Invocation(_) = &token.body {
            return Err(NucTokenBuildError::CannotExtendInvocation);
        }

        let mut proofs = vec![root_proof];
        proofs.extend(proofs_chain);

        Ok(Self {
            body: vec![],
            audience: None,
            subject: Some(token.subject),
            not_before: None,
            expires_at: None,
            command: Some(token.command.clone()),
            meta: None,
            nonce: vec![],
            proofs,
        })
    }

    /// Creates a chained delegation builder from serialized Nuc tokens.
    ///
    /// This is a convenience method that combines decoding, signature validation,
    /// and chain extension into a single operation.
    ///
    /// # Errors
    ///
    /// Returns an error if decoding fails, signature validation fails,
    /// or the decoded token is an invocation.
    pub fn extending_from_serialized(nucs: &str) -> Result<Self, NucTokenBuildError> {
        let envelope = NucTokenEnvelope::decode(nucs)
            .map_err(|e| NucTokenBuildError::ProofDecode(e.to_string()))?
            .validate_signatures()
            .map_err(|e| NucTokenBuildError::ProofDecode(e.to_string()))?;
        Self::extending(envelope)
    }

    /// Adds a policy constraint to this delegation.
    ///
    /// Policies restrict how the delegated authority may be used.
    /// Multiple policies can be added and will all be enforced.
    pub fn policy(mut self, policy: Policy) -> Self {
        self.body.push(policy);
        self
    }

    /// Adds multiple policy constraints to this delegation.
    ///
    /// This is a convenience method for adding several policies at once.
    pub fn policies<I>(mut self, new_policies: I) -> Self
    where
        I: IntoIterator<Item=Policy>,
    {
        self.body.extend(new_policies);
        self
    }

    /// Signs the delegation token and returns it as an envelope.
    ///
    /// The envelope contains the signed token and any proof tokens from the chain.
    ///
    /// # Errors
    ///
    /// Returns an error if required fields are missing or signing fails.
    pub async fn sign(self, signer: &impl Signer) -> Result<NucTokenEnvelope<SignaturesValidated>, NucTokenBuildError> {
        // Prepare the token body
        let token_body = TokenBody::Delegation(self.body.clone());

        // Build and sign
        let (token, header, signature, proofs) = self.build_and_sign_internal(signer, token_body).await?;

        // Create the raw Nuc
        let header_bytes =
            serde_json::to_vec(&header).map_err(|e| NucTokenBuildError::EncodingHeader(e.to_string()))?;
        let payload_bytes = serde_json::to_vec(&token).map_err(|e| NucTokenBuildError::EncodingToken(e.to_string()))?;

        let raw = RawNuc { header: header_bytes, payload: payload_bytes, signature };

        let decoded_token =
            DecodedNucToken::from_raw(raw).map_err(|e| NucTokenBuildError::EncodingToken(e.to_string()))?;

        // Create the envelope
        let envelope = NucTokenEnvelope { token: decoded_token, proofs, _unused: std::marker::PhantomData };

        Ok(envelope)
    }

    /// Signs the delegation token and returns it as a serialized string.
    ///
    /// The serialized format includes the token and all proofs in the chain,
    /// suitable for transmission over the network.
    ///
    /// # Errors
    ///
    /// Returns an error if required fields are missing, signing fails,
    /// or serialization fails.
    pub async fn sign_and_serialize(self, signer: &impl Signer) -> Result<String, NucTokenBuildError> {
        // Prepare the token body
        let token_body = TokenBody::Delegation(self.body.clone());

        // Build and sign
        let (token, header, signature, proofs) = self.build_and_sign_internal(signer, token_body).await?;

        // Serialize to base64
        let header_b64 = to_base64_json(&header).map_err(|e| NucTokenBuildError::EncodingHeader(e.to_string()))?;
        let payload_b64 = to_base64_json(&token).map_err(|e| NucTokenBuildError::EncodingToken(e.to_string()))?;
        let signature_b64 = to_base64(&signature);

        // Build output string
        let mut output = format!("{header_b64}.{payload_b64}.{signature_b64}");
        for proof in proofs {
            output.push('/');
            output.push_str(&proof.to_nuc_str());
        }

        Ok(output)
    }
}

impl Default for InvocationBuilder {
    fn default() -> Self {
        Self {
            body: serde_json::Value::Object(Default::default()),
            audience: None,
            subject: None,
            not_before: None,
            expires_at: None,
            command: None,
            meta: None,
            nonce: vec![],
            proofs: vec![],
        }
    }
}

impl InvocationBuilder {
    /// Creates a new root invocation token builder.
    ///
    /// Use this when creating an invocation without a delegation chain.
    /// Note that most invocations should use `extending()` to consume
    /// authority from a delegation.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an invocation builder from a proof envelope.
    ///
    /// This method inherits the `subject` and `command` from the proof token,
    /// and carries forward the entire proof chain from the envelope, creating an
    /// invocation that consumes the delegated authority.
    pub fn extending(proof: NucTokenEnvelope<SignaturesValidated>) -> Self {
        let (root_proof, proofs_chain) = proof.into_parts();
        let token = root_proof.token.clone();
        let mut proofs = vec![root_proof];
        proofs.extend(proofs_chain);

        Self {
            body: serde_json::Value::Object(Default::default()),
            audience: None,
            subject: Some(token.subject),
            not_before: None,
            expires_at: None,
            command: Some(token.command),
            meta: None,
            nonce: vec![],
            proofs,
        }
    }

    /// Creates an invocation builder from serialized Nuc tokens.
    ///
    /// This is a convenience method that combines decoding, signature validation,
    /// and invocation creation into a single operation.
    ///
    /// # Errors
    ///
    /// Returns an error if decoding or signature validation fails.
    pub fn extending_from_serialized(nucs: &str) -> Result<Self, NucTokenBuildError> {
        let envelope = NucTokenEnvelope::decode(nucs)
            .map_err(|e| NucTokenBuildError::ProofDecode(e.to_string()))?
            .validate_signatures()
            .map_err(|e| NucTokenBuildError::ProofDecode(e.to_string()))?;
        Ok(Self::extending(envelope))
    }

    /// Sets the arguments for this invocation.
    ///
    /// Arguments must be a JSON object. They provide parameters
    /// for the command being invoked.
    pub fn arguments<T>(mut self, args: T) -> Self
    where
        T: Into<serde_json::Value>,
    {
        self.body = args.into();
        self
    }

    /// Signs the invocation token and returns it as an envelope.
    ///
    /// The envelope contains the signed token and any proof tokens from the chain.
    ///
    /// # Errors
    ///
    /// Returns an error if required fields are missing, the arguments are not
    /// a JSON object, or signing fails.
    pub async fn sign(self, signer: &impl Signer) -> Result<NucTokenEnvelope<SignaturesValidated>, NucTokenBuildError> {
        // Validate and prepare the invocation body
        let obj = self
            .body
            .as_object()
            .ok_or_else(|| NucTokenBuildError::InvalidArguments("invocation arguments must be an object".to_string()))?
            .clone();

        let token_body = TokenBody::Invocation(obj);

        // Build and sign
        let (token, header, signature, proofs) = self.build_and_sign_internal(signer, token_body).await?;

        // Create the raw Nuc
        let header_bytes =
            serde_json::to_vec(&header).map_err(|e| NucTokenBuildError::EncodingHeader(e.to_string()))?;
        let payload_bytes = serde_json::to_vec(&token).map_err(|e| NucTokenBuildError::EncodingToken(e.to_string()))?;

        let raw = RawNuc { header: header_bytes, payload: payload_bytes, signature };

        let decoded_token =
            DecodedNucToken::from_raw(raw).map_err(|e| NucTokenBuildError::EncodingToken(e.to_string()))?;

        // Create the envelope
        let envelope = NucTokenEnvelope { token: decoded_token, proofs, _unused: std::marker::PhantomData };

        Ok(envelope)
    }

    /// Signs the invocation token and returns it as a serialized string.
    ///
    /// The serialized format includes the token and all proofs in the chain,
    /// suitable for transmission over the network.
    ///
    /// # Errors
    ///
    /// Returns an error if required fields are missing, the arguments are not
    /// a JSON object, signing fails, or serialization fails.
    pub async fn sign_and_serialize(self, signer: &impl Signer) -> Result<String, NucTokenBuildError> {
        // Validate and prepare the invocation body
        let obj = self
            .body
            .as_object()
            .ok_or_else(|| NucTokenBuildError::InvalidArguments("invocation arguments must be an object".to_string()))?
            .clone();

        let token_body = TokenBody::Invocation(obj);

        // Build and sign
        let (token, header, signature, proofs) = self.build_and_sign_internal(signer, token_body).await?;

        // Serialize to base64
        let header_b64 = to_base64_json(&header).map_err(|e| NucTokenBuildError::EncodingHeader(e.to_string()))?;
        let payload_b64 = to_base64_json(&token).map_err(|e| NucTokenBuildError::EncodingToken(e.to_string()))?;
        let signature_b64 = to_base64(&signature);

        // Build output string
        let mut output = format!("{header_b64}.{payload_b64}.{signature_b64}");
        for proof in proofs {
            output.push('/');
            output.push_str(&proof.to_nuc_str());
        }

        Ok(output)
    }
}

/// Errors that can occur when building Nuc tokens.
#[derive(Debug, thiserror::Error)]
pub enum NucTokenBuildError {
    /// A required field was not set on the builder.
    ///
    /// The audience, subject, and command fields must be set before signing.
    #[error("required field missing: {0}")]
    MissingField(&'static str),

    /// Failed to encode the token header as JSON.
    #[error("encoding header: {0}")]
    EncodingHeader(String),

    /// Failed to encode the token payload as JSON.
    #[error("encoding token: {0}")]
    EncodingToken(String),

    /// The signing operation failed.
    ///
    /// This typically indicates an issue with the signer or key material.
    #[error("signing failed: {0}")]
    Signing(#[from] SigningError),

    /// Failed to decode or validate a proof token.
    ///
    /// This occurs when extending from serialized tokens.
    #[error("proof decoding failed: {0}")]
    ProofDecode(String),

    /// The invocation arguments are invalid.
    ///
    /// Invocation arguments must be a JSON object.
    #[error("invalid arguments: {0}")]
    InvalidArguments(String),

    /// Attempted to create a delegation extending an invocation.
    ///
    /// Delegations can only extend other delegations, not invocations.
    #[error("cannot extend an invocation")]
    CannotExtendInvocation,
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
    use crate::builder::{DelegationBuilder, InvocationBuilder};
    use crate::signer::Eip712Signer;
    use crate::{
        did::Did,
        envelope::NucTokenEnvelope,
        keypair::Keypair,
        signer::{DidMethod, Signer},
    };
    use ethers::prelude::LocalWallet;
    use ethers::types::transaction::eip712::EIP712Domain;
    use serde_json::json;
    use std::default::Default;

    #[tokio::test]
    #[allow(deprecated)]
    async fn heterogeneous_chain() {
        // Setup - Define the actors in the delegation chain
        // Root authority (did:nil)
        let root_keypair = Keypair::generate();
        let root_signer = root_keypair.signer(DidMethod::Nil);

        // Intermediate authority (did:ethr)
        let eth_wallet = LocalWallet::new(&mut rand::thread_rng());
        let domain = EIP712Domain { name: Some("Nuc".into()), version: Some("1.0.0".into()), ..Default::default() };
        let ethr_signer = Eip712Signer::new(domain, eth_wallet.clone());

        // Final actor (did:key)
        let final_keypair = Keypair::generate();
        let final_signer = final_keypair.signer(DidMethod::Key);

        // Step 1 - Root grants authority to the `ethr` identity.
        let root_envelope = DelegationBuilder::new()
            .audience(Did::key([0xaa; 33]))
            .subject(*ethr_signer.did())
            .command(["nil", "db"])
            .sign(&root_signer)
            .await
            .expect("building root nuc failed");

        // Step 2: `ethr` identity delegates its authority to the `final` identity
        let ethr_envelope = DelegationBuilder::extending(root_envelope)
            .expect("extending from root failed")
            .audience(Did::key([0xaa; 33]))
            .subject(*final_signer.did())
            .sign(&ethr_signer)
            .await
            .expect("building ethr delegation failed");

        // Step 3: Final actor invokes a command
        let final_invocation = InvocationBuilder::extending(ethr_envelope)
            .audience(Did::key([0xaa; 33]))
            .subject(*final_signer.did())
            .command(["nil", "db", "read"])
            .arguments(json!({}))
            .sign_and_serialize(&final_signer)
            .await
            .expect("building final invocation failed");

        let final_envelope = NucTokenEnvelope::decode(&final_invocation)
            .expect("decoding final invocation failed")
            .validate_signatures()
            .expect("final chain validation failed");

        assert_eq!(final_envelope.proofs().len(), 2, "invocation envelope should have two proofs");
    }
}
