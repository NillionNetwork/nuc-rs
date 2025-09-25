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
use k256::PublicKey;
use std::{
    collections::{HashMap, HashSet},
    iter,
};

pub use error::{ValidationError, ValidationKind};

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
    /// Require an invocation for the given DID.
    Invocation(Did),

    /// Require a delegation for the given DID.
    Delegation(Did),

    /// Apply no token type requirements, meaning we're okay with any invocation and/or delegation.
    #[default]
    None,
}

/// A Nuc validator.
pub struct NucValidator {
    root_keys: HashSet<Box<[u8]>>,
    time_provider: Box<dyn TimeProvider>,
}

impl NucValidator {
    /// Construct a new Nuc validator.
    pub fn new(root_keys: &[PublicKey]) -> Self {
        let root_keys = root_keys.iter().map(|pk| pk.to_sec1_bytes()).collect();
        Self { root_keys, time_provider: Box::new(SystemClockTimeProvider) }
    }

    /// Validate a Nuc.
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
#[derive(Debug)]
pub struct ValidatedNucToken {
    /// The token.
    pub token: NucToken,

    /// The proofs for the token.
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
