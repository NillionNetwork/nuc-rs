use crate::{
    did::Did,
    envelope::DecodedNucToken,
    token::{NucToken, ProofHash, TokenBody},
};
use chrono::{DateTime, Utc};
use itertools::Itertools;
use std::collections::{HashMap, HashSet};

use super::error::{ValidationError, ValidationKind};
use super::{ValidationParameters, temporal};

const REVOCATION_COMMAND: &[&str] = &["nuc", "revoke"];

pub(super) fn validate_proofs(
    token: &NucToken,
    proofs: &[&NucToken],
    root_keys: &HashSet<[u8; 33]>,
) -> Result<(), ValidationError> {
    if !root_keys.is_empty() {
        // The root issuer of this token is either the last proof issuer or the issuer of the
        // token itself.
        let root_issuer = &proofs.last().unwrap_or(&token).issuer;

        // Check the root issuer's public key is in the set of allowed root keys
        let root_key_found = match root_issuer {
            #[allow(deprecated)]
            Did::Nil { public_key } => root_keys.contains(public_key.as_slice()),
            Did::Key { public_key } => root_keys.contains(public_key.as_slice()),
            Did::Ethr { .. } => {
                // TODO - don't validate against root keys yet
                false
            }
        };

        if !root_key_found {
            return Err(ValidationError::Validation(ValidationKind::RootKeySignatureMissing));
        }
    }

    for proof in proofs {
        match proof.body {
            TokenBody::Delegation(_) => (),
            TokenBody::Invocation(_) => {
                return Err(ValidationError::Validation(ValidationKind::ProofsMustBeDelegations));
            }
        };
    }
    Ok(())
}

pub(super) fn validate_token_chain<'a, I>(
    mut tokens: I,
    parameters: &ValidationParameters,
    current_time: DateTime<Utc>,
) -> Result<(), ValidationError>
where
    I: Iterator<Item = &'a NucToken> + Clone,
{
    for (previous, current) in tokens.clone().tuple_windows() {
        validate_relationship_properties(previous, current)?;
    }
    for token in tokens.clone() {
        temporal::validate_temporal_properties(token, &current_time)?;
    }
    for token in tokens.clone() {
        if let TokenBody::Delegation(policies) = &token.body {
            super::policy::validate_policies_properties(policies, parameters)?;
        }
    }
    if let Some(token) = tokens.nth(1) {
        validate_condition(token.issuer == token.subject, ValidationKind::SubjectNotInChain)?;
    }
    Ok(())
}

fn validate_relationship_properties(previous: &NucToken, current: &NucToken) -> Result<(), ValidationError> {
    validate_condition(previous.audience == current.issuer, ValidationKind::IssuerAudienceMismatch)?;
    validate_condition(previous.subject == current.subject, ValidationKind::DifferentSubjects)?;
    validate_condition(
        current.command.is_attenuation_of(&previous.command) || current.command.0 == REVOCATION_COMMAND,
        ValidationKind::CommandNotAttenuated,
    )?;
    if let Some((previous_not_before, current_not_before)) = previous.not_before.zip(current.not_before) {
        validate_condition(previous_not_before <= current_not_before, ValidationKind::NotBeforeBackwards)?;
    }
    Ok(())
}

// Create a chain of tokens linked by their proof hashes.
pub(super) fn sort_proofs(head_hash: ProofHash, proofs: &[DecodedNucToken]) -> Result<Vec<&NucToken>, ValidationError> {
    // Do a first pass and index them all by hash.
    let mut indexed_proofs = HashMap::new();
    for proof in proofs {
        let hash = proof.compute_hash();
        indexed_proofs.insert(hash, &proof.token);
    }

    // Now start from the head hash and walk backwards until we hit the root.
    let mut next_hash = head_hash;
    let mut chain = Vec::new();
    loop {
        let proof = indexed_proofs.remove(&next_hash).ok_or(ValidationKind::MissingProof)?;
        chain.push(proof);
        match proof.proofs.as_slice() {
            // We hit the root NUC
            [] => break,
            // Continue with this one
            [hash] => next_hash = *hash,
            _ => return Err(ValidationKind::TooManyProofs.into()),
        };
    }
    // Make sure there's nothing left
    if indexed_proofs.is_empty() { Ok(chain) } else { Err(ValidationKind::UnchainedProofs.into()) }
}

pub(super) fn validate_condition(condition: bool, error_kind: ValidationKind) -> Result<(), ValidationError> {
    if condition { Ok(()) } else { Err(ValidationError::Validation(error_kind)) }
}
