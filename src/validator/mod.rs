mod chain;
pub mod error;
mod policy;
mod temporal;

#[cfg(test)]
mod tests;

use crate::{
    did::Did,
    envelope::NucTokenEnvelope,
    token::{NucToken, TokenBody},
};
use chrono::{DateTime, Utc};
use std::{
    collections::{HashMap, HashSet},
    iter,
};

pub use error::{ValidationError, ValidationKind};

/// An error during the creation of a Nuc validator.
#[derive(Debug, thiserror::Error)]
pub enum NucValidatorCreationError {
    /// An invalid public key was provided.
    #[error("invalid public key provided: {0}")]
    InvalidPublicKey(#[from] k256::elliptic_curve::Error),
}

const MAX_CHAIN_LENGTH: usize = 5;
const MAX_POLICY_WIDTH: usize = 10;
const MAX_POLICY_DEPTH: usize = 5;

/// The result of validating a Nuc token.
pub type ValidationResult = Result<(), ValidationError>;

/// Parameters to be used during validation.
#[derive(Debug)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct ValidationParameters {
    /// The maximum allowed chain length.
    pub max_chain_length: usize,

    /// The maximum width of a policy.
    pub max_policy_width: usize,

    /// The maximum depth of a policy.
    pub max_policy_depth: usize,

    /// The requirements for the token being validated.
    pub token_requirements: TokenTypeRequirements,
}

impl Default for ValidationParameters {
    fn default() -> Self {
        Self {
            max_chain_length: MAX_CHAIN_LENGTH,
            max_policy_width: MAX_POLICY_WIDTH,
            max_policy_depth: MAX_POLICY_DEPTH,
            token_requirements: Default::default(),
        }
    }
}

/// The requirements for the token being validated.
#[derive(Debug, Default)]
#[cfg_attr(test, derive(serde::Serialize), serde(rename_all = "snake_case"))]
pub enum TokenTypeRequirements {
    /// Requires an invocation for the given DID.
    Invocation(Did),

    /// Requires a delegation for the given DID.
    Delegation(Did),

    /// Applies no token type requirements, meaning we're okay with any invocation and/or delegation.
    #[default]
    None,
}

/// A Nuc validator.
pub struct NucValidator {
    root_keys: HashSet<[u8; 33]>,
    time_provider: Box<dyn TimeProvider>,
}

impl NucValidator {
    /// Construct a new Nuc validator.
    ///
    /// This establishes the root of trust for token validation.
    ///
    /// # Arguments
    ///
    /// * `root_keys` - An iterator of 33-byte compressed secp256k1 public keys. Any valid
    ///   token chain must be rooted in a token signed by one of these keys.
    pub fn new<I>(root_keys: I) -> Result<Self, NucValidatorCreationError>
    where
        I: IntoIterator<Item = [u8; 33]>,
    {
        use k256::PublicKey;

        let mut parsed_keys = HashSet::new();
        for key_bytes in root_keys {
            PublicKey::from_sec1_bytes(&key_bytes)?;
            parsed_keys.insert(key_bytes);
        }
        Ok(Self { root_keys: parsed_keys, time_provider: Box::new(SystemClockTimeProvider) })
    }

    /// Validates a Nuc token envelope.
    ///
    /// This method performs a comprehensive validation of the token and its entire proof chain, including:
    /// - Signature verification for all tokens in the chain.
    /// - Temporal checks (expiration and not-before).
    /// - Structural integrity of the delegation chain.
    /// - Adherence to policy and command attenuations.
    /// - Satisfaction of all policies for invocations.
    ///
    /// # Arguments
    ///
    /// * `envelope` - The Nuc token envelope to validate.
    /// * `parameters` - The validation parameters to use.
    /// * `context` - An external context map for policy evaluation.
    ///
    /// # Returns
    ///
    /// A [`ValidatedNucToken`] if validation is successful.
    ///
    /// # Errors
    ///
    /// Returns a [`ValidationError`] if any validation check fails.
    pub fn validate(
        &self,
        envelope: NucTokenEnvelope,
        parameters: ValidationParameters,
        context: &HashMap<&str, serde_json::Value>,
    ) -> Result<ValidatedNucToken, ValidationError> {
        // Perform this one check before validating signatures to avoid doing contly work
        if envelope.proofs().len().saturating_add(1) > parameters.max_chain_length {
            return Err(ValidationError::Validation(ValidationKind::ChainTooLong));
        }

        let token = &envelope.token().token;
        let proofs = match token.proofs.as_slice() {
            [] => Vec::new(),
            [hash] => chain::sort_proofs(*hash, envelope.proofs())?,
            _ => return Err(ValidationKind::TooManyProofs.into()),
        };

        // Create a sequence [root, ..., token]
        let token_chain = iter::once(token).chain(proofs.iter().copied()).rev();
        let now = self.time_provider.current_time();
        chain::validate_proofs(token, &proofs, &self.root_keys)?;
        chain::validate_token_chain(token_chain, &parameters, now)?;
        validate_token(token, &proofs, &parameters.token_requirements, context)?;

        // Signature validation is done at the end as it's arguably the most expensive part of the
        // validation process.
        let envelope = envelope.validate_signatures().map_err(|_| ValidationKind::InvalidSignatures)?;
        let (token, proofs) = envelope.into_parts();
        let validated_token =
            ValidatedNucToken { token: token.token, proofs: proofs.into_iter().map(|proof| proof.token).collect() };
        Ok(validated_token)
    }
}

// Validations applied only to the token itself
fn validate_token(
    token: &NucToken,
    proofs: &[&NucToken],
    requirements: &TokenTypeRequirements,
    context: &HashMap<&str, serde_json::Value>,
) -> ValidationResult {
    match &token.body {
        TokenBody::Delegation(_) => {
            match requirements {
                TokenTypeRequirements::Invocation(_) => {
                    return Err(ValidationError::Validation(ValidationKind::NeedInvocation));
                }
                TokenTypeRequirements::Delegation(did) => {
                    chain::validate_condition(&token.audience == did, ValidationKind::InvalidAudience)?
                }
                TokenTypeRequirements::None => (),
            };
        }
        TokenBody::Invocation(_) => {
            match requirements {
                TokenTypeRequirements::Invocation(did) => {
                    chain::validate_condition(&token.audience == did, ValidationKind::InvalidAudience)?;
                }
                TokenTypeRequirements::Delegation(_) => {
                    return Err(ValidationError::Validation(ValidationKind::NeedDelegation));
                }
                TokenTypeRequirements::None => (),
            }
            let token_json = serde_json::to_value(token).map_err(ValidationError::Serde)?;
            for proof in proofs {
                policy::validate_policy_matches(proof, &token_json, context)?;
            }
        }
    };
    Ok(())
}

/// A validated Nuc token along with its proofs.
///
/// This structure represents a token that has successfully passed all validation checks,
/// including signature verification, temporal validation, and policy evaluation.
#[derive(Debug)]
pub struct ValidatedNucToken {
    /// The validated token.
    pub token: NucToken,

    /// The validated proofs for the token.
    ///
    /// These are sorted in the way the chain was built, starting from `token`'s proof. That is:
    ///
    /// ```no_compile
    /// token proof -> proofs[0] -> ... -> root_token.
    /// ```
    pub proofs: Vec<NucToken>,
}

trait TimeProvider: Send + Sync + 'static {
    fn current_time(&self) -> DateTime<Utc>;
}

struct SystemClockTimeProvider;

impl TimeProvider for SystemClockTimeProvider {
    fn current_time(&self) -> DateTime<Utc> {
        Utc::now()
    }
}
