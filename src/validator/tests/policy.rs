use super::fixtures::*;
use crate::{
    builder::{DelegationBuilder, InvocationBuilder},
    did::Did,
    policy,
    signer::DidMethod,
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
    let key = keypair();
    let root_signer = root_signer();
    let key_signer = key.signer(DidMethod::Key);
    let subject = key.to_did(DidMethod::Key);

    // Root delegation with policy requiring ".foo" = 42
    let root = DelegationBuilder::new()
        .policy(policy::op::eq(".foo", json!(42)))
        .subject(subject.clone())
        .audience(key.to_did(DidMethod::Key))
        .command(["nil"])
        .sign(&root_signer)
        .await
        .expect("failed to build root");

    // Invocation with arguments that don't meet the policy (has "bar": 1337 but no "foo": 42)
    let invocation = InvocationBuilder::extending(root)
        .arguments(json!({"bar": 1337}))
        .audience(Did::key([0xaa; 33]))
        .command(["nil"])
        .sign(&key_signer)
        .await
        .expect("failed to build invocation");

    Asserter::default().assert_failure(invocation.unvalidate(), ValidationKind::PolicyNotMet);
}

#[tokio::test]
async fn last_policy_not_met() {
    let subject_key = keypair();
    let invocation_key = keypair();
    let root_signer = root_signer();
    let subject_signer = subject_key.signer(DidMethod::Key);
    let invocation_signer = invocation_key.signer(DidMethod::Key);
    let subject = subject_key.to_did(DidMethod::Key);

    // Root delegation without policy
    let root = DelegationBuilder::new()
        .subject(subject.clone())
        .audience(subject_key.to_did(DidMethod::Key))
        .command(["nil"])
        .sign(&root_signer)
        .await
        .expect("failed to build root");

    // Intermediate delegation with policy requiring ".foo" = 42
    let intermediate = DelegationBuilder::extending(root)
        .expect("failed to extend")
        .policy(policy::op::eq(".foo", json!(42)))
        .audience(invocation_key.to_did(DidMethod::Key))
        .command(["nil"])
        .sign(&subject_signer)
        .await
        .expect("failed to build intermediate");

    // Invocation with arguments that don't meet the policy
    let invocation = InvocationBuilder::extending(intermediate)
        .arguments(json!({"bar": 1337}))
        .audience(Did::key([0xaa; 33]))
        .command(["nil"])
        .sign(&invocation_signer)
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

    let key = keypair();
    let root_signer = root_signer();
    let key_signer = key.signer(DidMethod::Key);
    let subject = key.to_did(DidMethod::Key);

    // Root delegation with deeply nested policy
    let root = DelegationBuilder::new()
        .policy(policy)
        .subject(subject.clone())
        .audience(key.to_did(DidMethod::Key))
        .command(["nil"])
        .sign(&root_signer)
        .await
        .expect("failed to build root");

    let tail = DelegationBuilder::extending(root)
        .expect("failed to extend")
        .audience(Did::key([0xde; 33]))
        .command(["nil"])
        .sign(&key_signer)
        .await
        .expect("failed to build tail");

    Asserter::default().assert_failure(tail.unvalidate(), ValidationKind::PolicyTooDeep);
}

#[tokio::test]
async fn policy_array_too_wide() {
    let policies = vec![policy::op::eq(".foo", json!(42)); MAX_POLICY_WIDTH + 1];

    let key = keypair();
    let root_signer = root_signer();
    let key_signer = key.signer(DidMethod::Key);
    let subject = key.to_did(DidMethod::Key);

    // Root delegation with too many policies
    let mut root_builder =
        DelegationBuilder::new().subject(subject.clone()).audience(key.to_did(DidMethod::Key)).command(["nil"]);

    for policy in policies {
        root_builder = root_builder.policy(policy);
    }

    let root = root_builder.sign(&root_signer).await.expect("failed to build root");

    let tail = DelegationBuilder::extending(root)
        .expect("failed to extend")
        .audience(Did::key([0xde; 33]))
        .command(["nil"])
        .sign(&key_signer)
        .await
        .expect("failed to build tail");

    Asserter::default().assert_failure(tail.unvalidate(), ValidationKind::PolicyTooWide);
}

#[tokio::test]
async fn policy_too_wide() {
    let policies = vec![policy::op::eq(".foo", json!(42)); MAX_POLICY_WIDTH + 1];
    let policy = policy::op::and(policies);

    let key = keypair();
    let root_signer = root_signer();
    let key_signer = key.signer(DidMethod::Key);
    let subject = key.to_did(DidMethod::Key);

    // Root delegation with wide AND policy
    let root = DelegationBuilder::new()
        .policy(policy)
        .subject(subject.clone())
        .audience(key.to_did(DidMethod::Key))
        .command(["nil"])
        .sign(&root_signer)
        .await
        .expect("failed to build root");

    let tail = DelegationBuilder::extending(root)
        .expect("failed to extend")
        .audience(Did::key([0xde; 33]))
        .command(["nil"])
        .sign(&key_signer)
        .await
        .expect("failed to build tail");

    Asserter::default().assert_failure(tail.unvalidate(), ValidationKind::PolicyTooWide);
}
