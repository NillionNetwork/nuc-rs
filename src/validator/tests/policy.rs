use super::fixtures::*;
use crate::{
    builder::{DelegationBuilder, InvocationBuilder},
    did::Did,
    policy,
    validator::{MAX_POLICY_DEPTH, MAX_POLICY_WIDTH, error::ValidationKind, policy::PolicyTreeProperties},
};
use rstest::rstest;
use serde_json::json;

#[rstest]
#[case::operator(policy::op::eq(".field", json!(42)), PolicyTreeProperties { max_depth: 1, max_policy_width: 1 })]
#[case::any_od(policy::op::any_of(".field", &[json!(42), json!(1337)]), PolicyTreeProperties { max_depth: 1, max_policy_width: 2 })]
#[case::not(policy::op::not(policy::op::eq(".field", json!(42))), PolicyTreeProperties { max_depth: 2, max_policy_width: 1 })]
#[case::and_single(policy::op::and(&[policy::op::eq(".field", json!(42))]), PolicyTreeProperties { max_depth: 2, max_policy_width: 1 })]
#[case::or_single(policy::op::or(&[policy::op::eq(".field", json!(42))]), PolicyTreeProperties { max_depth: 2, max_policy_width: 1 })]
#[case::and_multi(
    policy::op::and(&[policy::op::eq(".field", json!(42)), policy::op::eq(".field", json!(42))]),
    PolicyTreeProperties { max_depth: 2, max_policy_width: 2 }
)]
#[case::or_multi(
    policy::op::or(&[policy::op::eq(".field", json!(42)), policy::op::eq(".field", json!(42))]),
    PolicyTreeProperties { max_depth: 2, max_policy_width: 2 }
)]
#[case::nested(
    policy::op::and(&[
        policy::op::not(policy::op::eq(".field", json!(42))),
        policy::op::any_of(".field", &[json!(42), json!(1337)])
    ]),
    PolicyTreeProperties { max_depth: 3, max_policy_width: 2 }
)]
fn policy_properties(#[case] policy: crate::policy::Policy, #[case] expected: PolicyTreeProperties) {
    let properties = PolicyTreeProperties::from(&policy);
    assert_eq!(properties, expected);
}

#[tokio::test]
async fn root_policy_not_met() {
    let invocation = build_invocation_with_one_proof(
        |delegation| delegation.policy(policy::op::eq(".foo", json!(42))),
        |invocation| invocation.arguments(json!({ "bar": 1337 })),
    )
    .await;

    Asserter::default().assert_failure(invocation.unvalidate(), ValidationKind::PolicyNotMet);
}

#[tokio::test]
async fn intermediate_policy_not_met() {
    let root_signer = root_signer();
    let subject_signer = signer();
    let subject_did = *subject_signer.did();
    let invocation_signer = signer();
    let invocation_did = *invocation_signer.did();

    // Root delegation without policy
    let root = DelegationBuilder::new()
        .subject(subject_did)
        .audience(subject_did)
        .command(["nil"])
        .sign(&*root_signer)
        .await
        .expect("failed to build root");

    // Intermediate delegation with policy requiring ".foo" = 42
    let intermediate = DelegationBuilder::extending(root)
        .expect("failed to extend")
        .policy(policy::op::eq(".foo", json!(42)))
        .audience(invocation_did)
        .command(["nil"])
        .sign(&*subject_signer)
        .await
        .expect("failed to build intermediate");

    // Invocation with arguments that don't meet the policy
    let invocation = InvocationBuilder::extending(intermediate)
        .arguments(json!({"bar": 1337}))
        .audience(Did::key([0xaa; 33]))
        .command(["nil"])
        .sign(&*invocation_signer)
        .await
        .expect("failed to build invocation");

    Asserter::default().assert_failure(invocation.unvalidate(), ValidationKind::PolicyNotMet);
}

#[tokio::test]
async fn policy_too_deep() {
    // Build a not(not(not...(op))) chain that's one too deep
    let mut policy = policy::op::eq(".foo", json!(42));
    for _ in 0..MAX_POLICY_DEPTH {
        policy = policy::op::not(policy);
    }

    let chain = build_two_link_delegation_chain(|root| root.policy(policy), |second| second).await;

    Asserter::default().assert_failure(chain.unvalidate(), ValidationKind::PolicyTooDeep);
}

#[tokio::test]
async fn policy_array_too_wide() {
    let policies = vec![policy::op::eq(".foo", json!(42)); MAX_POLICY_WIDTH + 1];

    let chain = build_two_link_delegation_chain(|root| root.policies(policies), |second| second).await;

    Asserter::default().assert_failure(chain.unvalidate(), ValidationKind::PolicyTooWide);
}

#[tokio::test]
async fn policy_too_wide() {
    let policies = vec![policy::op::eq(".foo", json!(42)); MAX_POLICY_WIDTH + 1];
    let policy = policy::op::and(policies);

    let chain = build_two_link_delegation_chain(|root| root.policy(policy), |second| second).await;

    Asserter::default().assert_failure(chain.unvalidate(), ValidationKind::PolicyTooWide);
}
