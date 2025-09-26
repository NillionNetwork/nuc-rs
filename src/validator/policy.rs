use crate::{
    policy::{ConnectorPolicy, Operator, OperatorPolicy, Policy},
    token::{NucToken, TokenBody},
};
use std::ops::Deref;

use super::ValidationParameters;
use super::chain::validate_condition;
use super::error::{ValidationError, ValidationKind};

pub(super) fn validate_policies_properties(
    policies: &[Policy],
    parameters: &ValidationParameters,
) -> Result<(), ValidationError> {
    validate_condition(policies.len() <= parameters.max_policy_width, ValidationKind::PolicyTooWide)?;
    for policy in policies {
        let properties = PolicyTreeProperties::from(policy);
        validate_condition(properties.max_policy_width <= parameters.max_policy_width, ValidationKind::PolicyTooWide)?;
        validate_condition(properties.max_depth <= parameters.max_policy_depth, ValidationKind::PolicyTooDeep)?;
    }
    Ok(())
}

pub(super) fn validate_policy_matches(
    token: &NucToken,
    invocation: &serde_json::Value,
    context: &std::collections::HashMap<&str, serde_json::Value>,
) -> Result<(), ValidationError> {
    match &token.body {
        TokenBody::Delegation(policies) => {
            for policy in policies {
                if !policy.evaluate(invocation, context) {
                    return Err(ValidationError::Validation(ValidationKind::PolicyNotMet));
                }
            }
            Ok(())
        }
        TokenBody::Invocation(_) => Err(ValidationError::Validation(ValidationKind::ProofsMustBeDelegations)),
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct PolicyTreeProperties {
    pub max_depth: usize,
    pub max_policy_width: usize,
}

impl From<&Policy> for PolicyTreeProperties {
    fn from(policy: &Policy) -> Self {
        match policy {
            Policy::Operator(policy) => Self::from(policy),
            Policy::Connector(policy) => Self::from(policy),
        }
    }
}

impl From<&OperatorPolicy> for PolicyTreeProperties {
    fn from(policy: &OperatorPolicy) -> Self {
        use Operator::*;
        match &policy.operator {
            Equals(_) | NotEquals(_) => Self { max_depth: 1, max_policy_width: 1 },
            AnyOf(values) => Self { max_depth: 1, max_policy_width: values.len() },
        }
    }
}

impl From<&ConnectorPolicy> for PolicyTreeProperties {
    fn from(policy: &ConnectorPolicy) -> Self {
        use ConnectorPolicy::*;
        let mut output = match policy {
            And(policies) | Or(policies) => {
                let mut output = PolicyTreeProperties { max_depth: 0, max_policy_width: policies.len() };
                for policy in policies {
                    let properties = Self::from(policy);
                    output.max_depth = output.max_depth.max(properties.max_depth);
                    output.max_policy_width = output.max_policy_width.max(properties.max_policy_width);
                }
                output
            }
            Not(policy) => Self::from(policy.deref()),
        };
        output.max_depth += 1;
        output
    }
}
