use std::fmt;

/// An error during the validation of a token.
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("validation failed: {0}")]
    Validation(ValidationKind),

    #[error("invalid JSON token: {0}")]
    Serde(serde_json::Error),
}

impl From<ValidationKind> for ValidationError {
    fn from(kind: ValidationKind) -> Self {
        Self::Validation(kind)
    }
}

/// A kind of validation that was violated.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ValidationKind {
    ChainTooLong,
    CommandNotAttenuated,
    DifferentSubjects,
    InvalidAudience,
    InvalidSignatures,
    IssuerAudienceMismatch,
    MissingProof,
    NeedDelegation,
    NeedInvocation,
    NotBeforeBackwards,
    NotBeforeNotMet,
    PolicyNotMet,
    PolicyTooDeep,
    PolicyTooWide,
    ProofsMustBeDelegations,
    RootKeySignatureMissing,
    SubjectNotInChain,
    TokenExpired,
    TooManyProofs,
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
            RootKeySignatureMissing => "root NUC is not signed by root keypair",
            SubjectNotInChain => "subject not in chain",
            TokenExpired => "token is expired",
            TooManyProofs => "up to one `prf` in a token is allowed",
            UnchainedProofs => "extra proofs not part of chain provided",
        };
        write!(f, "{text}")
    }
}
