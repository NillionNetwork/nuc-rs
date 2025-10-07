use std::fmt;

/// An error during the validation of a Nuc token.
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    /// A specific validation rule was violated.
    #[error("validation failed: {0}")]
    Validation(ValidationKind),

    /// The token contains malformed JSON.
    #[error("invalid JSON token: {0}")]
    Serde(serde_json::Error),
}

impl From<ValidationKind> for ValidationError {
    fn from(kind: ValidationKind) -> Self {
        Self::Validation(kind)
    }
}

/// The specific kind of validation failure.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ValidationKind {
    /// The token's proof chain exceeds the maximum allowed length.
    ChainTooLong,

    /// The command is not an attenuation of the parent command.
    CommandNotAttenuated,

    /// Different subjects appear in the token chain.
    DifferentSubjects,

    /// The token's audience is invalid for the validation requirements.
    InvalidAudience,

    /// One or more signatures in the token chain are invalid.
    InvalidSignatures,

    /// The issuer and audience fields do not match the expected relationship.
    IssuerAudienceMismatch,

    /// A required proof is missing from the token chain.
    MissingProof,

    /// A delegation was required but not provided.
    NeedDelegation,

    /// An invocation was required but not provided.
    NeedInvocation,

    /// The not-before time moves backward in the token chain.
    NotBeforeBackwards,

    /// The current time is before the token's not-before time.
    NotBeforeNotMet,

    /// A policy requirement was not satisfied.
    PolicyNotMet,

    /// The policy exceeds the maximum allowed depth.
    PolicyTooDeep,

    /// The policy exceeds the maximum allowed width.
    PolicyTooWide,

    /// A proof in the chain is not a delegation.
    ProofsMustBeDelegations,

    /// The root token is not signed by a trusted root key.
    RootKeySignatureMissing,

    /// The token's subject does not appear in the chain.
    SubjectNotInChain,

    /// The token has expired.
    TokenExpired,

    /// The token contains more than one proof reference.
    TooManyProofs,

    /// Extra proofs that are not part of the chain were provided.
    UnchainedProofs,
}

impl fmt::Display for ValidationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ValidationKind::*;
        let text = match self {
            ChainTooLong => "token chain is too long",
            CommandNotAttenuated => "command is not an attenuation",
            DifferentSubjects => "different subjects in chain",
            InvalidAudience => "invalid audience",
            InvalidSignatures => "invalid signatures",
            IssuerAudienceMismatch => "issuer/audience mismatch",
            MissingProof => "proof is missing",
            NeedDelegation => "token must be a delegation",
            NeedInvocation => "token must be an invocation",
            NotBeforeBackwards => "`not before` cannot move backwards",
            NotBeforeNotMet => "`not before` date not met",
            PolicyNotMet => "policy not met",
            PolicyTooDeep => "policy is too deep",
            PolicyTooWide => "policy is too wide",
            ProofsMustBeDelegations => "proofs must be delegations",
            RootKeySignatureMissing => "root NUC is not signed by root",
            SubjectNotInChain => "subject not in chain",
            TokenExpired => "token is expired",
            TooManyProofs => "up to one `prf` in a token is allowed",
            UnchainedProofs => "extra proofs not part of chain provided",
        };
        write!(f, "{text}")
    }
}
