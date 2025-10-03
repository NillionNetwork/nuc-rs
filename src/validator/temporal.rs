use crate::token::NucToken;
use chrono::{DateTime, Utc};

use super::chain::validate_condition;
use super::error::{ValidationError, ValidationKind};

pub(super) fn validate_temporal_properties(token: &NucToken, now: &DateTime<Utc>) -> Result<(), ValidationError> {
    validate_condition(token.expires_at.map(|t| now < &t).unwrap_or(true), ValidationKind::TokenExpired)?;
    validate_condition(token.not_before.map(|t| now >= &t).unwrap_or(true), ValidationKind::NotBeforeNotMet)?;
    Ok(())
}
