use super::fixtures::*;
use crate::{
    NucSigner,
    builder::{DelegationBuilder, InvocationBuilder, NucTokenBuildError, to_base64},
    did::Did,
    envelope::{NucTokenEnvelope, from_base64},
    policy,
    validator::{TokenTypeRequirements, ValidatedNucToken, ValidationParameters, error::ValidationKind},
};
use serde_json::json;
use std::collections::HashMap;

#[tokio::test]
async fn unlinked_chain() {
    let root_signer = root_signer();
    let key_signer = signer();
    let key_did = *key_signer.did();

    // Build the first delegation token
    let first = delegation(key_did)
        .command(["nil"])
        .audience(key_did)
        .sign(&*root_signer)
        .await
        .expect("failed to build first");

    // Build the second token extending the first
    let second = DelegationBuilder::extending(first.clone())
        .expect("failed to extend")
        .audience(Did::key([0xde; 33]))
        .command(["nil"])
        .sign(&*key_signer)
        .await
        .expect("failed to build second");

    // Now add an unlinked token (not chained properly)
    let unlinked =
        delegation(key_did).command(["nil"]).sign_and_serialize(&*root_signer).await.expect("failed to build unlinked");

    // Manually construct an envelope with the unlinked proof
    let second_encoded = second.unvalidate().encode();
    let token = format!("{}/{}", second_encoded, unlinked);
    let envelope = NucTokenEnvelope::decode(&token).expect("decode failed");
    Asserter::default().assert_failure(envelope, ValidationKind::UnchainedProofs);
}

#[tokio::test]
async fn chain_too_long() {
    let root_signer = root_signer();
    let key_signer = signer();
    let key_did = *key_signer.did();

    // Build first token
    let first = delegation(key_did)
        .command(["nil"])
        .audience(key_did)
        .sign(&*root_signer)
        .await
        .expect("failed to build first");

    // Build second token extending first
    let second = DelegationBuilder::extending(first)
        .expect("failed to extend")
        .audience(key_did)
        .command(["nil"])
        .sign(&*key_signer)
        .await
        .expect("failed to build second");

    // Build third token extending second
    let third = DelegationBuilder::extending(second)
        .expect("failed to extend")
        .audience(Did::key([0xde; 33]))
        .command(["nil"])
        .sign(&*key_signer)
        .await
        .expect("failed to build third");

    let parameters = ValidationParameters { max_chain_length: 2, ..Default::default() };
    Asserter::new(parameters).assert_failure(third.unvalidate(), ValidationKind::ChainTooLong);
}

#[tokio::test]
async fn command_not_attenuated() {
    let chain = build_two_link_delegation_chain(
        |root| root.command(["nil"]),
        |second| second.command(["bar"]), // Command /bar is not an attenuation if /nil
    )
    .await;

    Asserter::default().assert_failure(chain.unvalidate(), ValidationKind::CommandNotAttenuated);
}

#[tokio::test]
async fn issuer_audience_mismatch() {
    let chain = build_two_link_delegation_chain(
        |root| root.audience(Did::key([0xaa; 33])), // Set a specific audience
        |second| second,                            // The second link's issuer will not match the root's audience
    )
    .await;

    Asserter::default().assert_failure(chain.unvalidate(), ValidationKind::IssuerAudienceMismatch);
}

#[tokio::test]
async fn invalid_audience_invocation() {
    let expected_did = Did::key([0xaa; 33]);
    let actual_did = Did::key([0xbb; 33]);

    let invocation =
        build_invocation_with_one_proof(|delegation| delegation, |invocation| invocation.audience(actual_did)).await;

    let parameters = ValidationParameters {
        token_requirements: TokenTypeRequirements::Invocation(expected_did),
        ..Default::default()
    };
    Asserter::new(parameters).assert_failure(invocation.unvalidate(), ValidationKind::InvalidAudience);
}

#[tokio::test]
async fn invalid_signature() {
    let root_signer = root_signer();
    let subject_did = signer().did().clone();

    let envelope = delegation(subject_did).command(["nil"]).sign(&*root_signer).await.expect("failed to build");

    let token = envelope.unvalidate().encode();
    let (base, signature) = token.rsplit_once(".").unwrap();

    // Change a byte in the signature
    let signature = from_base64(signature).unwrap();
    let mut signature = signature.clone();
    signature[0] ^= 1;
    let signature = to_base64(&signature);
    let token = format!("{base}.{signature}");
    let envelope = NucTokenEnvelope::decode(&token).expect("decode failed");

    // Don't require a root key signature
    let asserter = Asserter { root_keys: Vec::new(), ..Default::default() };
    asserter.assert_failure(envelope, ValidationKind::InvalidSignatures);
}

#[tokio::test]
async fn invalid_audience_delegation() {
    let expected_did = Did::key([0xaa; 33]);
    let actual_did = Did::key([0xbb; 33]);

    let chain = build_two_link_delegation_chain(|root| root, |second| second.audience(actual_did)).await;

    let parameters = ValidationParameters {
        token_requirements: TokenTypeRequirements::Delegation(expected_did),
        ..Default::default()
    };
    Asserter::new(parameters).assert_failure(chain.unvalidate(), ValidationKind::InvalidAudience);
}

#[tokio::test]
async fn missing_proof() {
    let root_signer = root_signer();
    let key_signer = signer();
    let key_did = *key_signer.did();

    // Build chain
    let first = delegation(key_did)
        .command(["nil"])
        .audience(key_did)
        .sign(&*root_signer)
        .await
        .expect("failed to build first");

    let second = DelegationBuilder::extending(first)
        .expect("failed to extend")
        .audience(Did::key([0xde; 33]))
        .command(["nil"])
        .sign(&*key_signer)
        .await
        .expect("failed to build second");

    // Keep the token without its proof
    let token = second.unvalidate().encode();
    let token = token.split_once("/").unwrap().0;
    let envelope = NucTokenEnvelope::decode(token).expect("invalid token");
    Asserter::default().assert_failure(envelope, ValidationKind::MissingProof);
}

#[tokio::test]
async fn need_delegation() {
    let invocation = build_invocation_with_one_proof(|delegation| delegation, |invocation| invocation).await;

    let parameters = ValidationParameters {
        token_requirements: TokenTypeRequirements::Delegation(Did::key([0xaa; 33])),
        ..Default::default()
    };
    Asserter::new(parameters).assert_failure(invocation.unvalidate(), ValidationKind::NeedDelegation);
}

#[tokio::test]
async fn need_invocation() {
    let chain = build_two_link_delegation_chain(|root| root, |second| second).await;

    let parameters = ValidationParameters {
        token_requirements: TokenTypeRequirements::Invocation(Did::key([0xaa; 33])),
        ..Default::default()
    };
    Asserter::new(parameters).assert_failure(chain.unvalidate(), ValidationKind::NeedInvocation);
}

#[tokio::test]
async fn proofs_must_be_delegations() {
    let root_signer = root_signer();
    let subject_signer = signer();
    let subject = *subject_signer.did();

    // Root is an invocation
    let root_invocation = InvocationBuilder::new()
        .arguments(json!({"bar": 1337}))
        .subject(subject)
        .audience(subject)
        .command(["nil"])
        .sign(&*root_signer)
        .await
        .expect("failed to build root invocation");

    // Attempting to create a delegation from an invocation proof should fail.
    let result = DelegationBuilder::extending(root_invocation);

    assert!(matches!(result, Err(NucTokenBuildError::CannotExtendInvocation)));
}

#[tokio::test]
async fn root_key_signature_missing() {
    let key_signer = signer();
    let key_did = *key_signer.did();

    // First delegation signed by non-root key
    let first =
        delegation(key_did).command(["nil"]).audience(key_did).sign(&*key_signer).await.expect("failed to build first");

    // Second delegation
    let second = DelegationBuilder::extending(first)
        .expect("failed to extend")
        .audience(Did::key([0xde; 33]))
        .command(["nil"])
        .sign(&*key_signer)
        .await
        .expect("failed to build second");

    Asserter::default().assert_failure(second.unvalidate(), ValidationKind::RootKeySignatureMissing);
}

#[tokio::test]
async fn subject_not_in_chain() {
    let subject_signer = signer();
    let subject_did = *subject_signer.did();
    let other_signer = signer();
    let other_did = *other_signer.did();
    let root_signer = root_signer();

    // Root delegation with subject_key as subject
    let first = delegation(subject_did)
        .command(["nil"])
        .audience(other_did)
        .sign(&*root_signer)
        .await
        .expect("failed to build first");

    // Second delegation signed by other_key (not subject_key)
    let second = DelegationBuilder::extending(first)
        .expect("failed to extend")
        .audience(Did::key([0xde; 33]))
        .command(["nil"])
        .sign(&*other_signer)
        .await
        .expect("failed to build second");

    Asserter::default().assert_failure(second.unvalidate(), ValidationKind::SubjectNotInChain);
}

#[tokio::test]
async fn valid_token() {
    let root_signer = root_signer();
    let subject_signer = signer();
    let subject_did = *subject_signer.did();
    let invocation_signer = signer();
    let invocation_did = *invocation_signer.did();
    let rpc_did = Did::key([0xaa; 33]);

    // Root delegation with policies
    let root = DelegationBuilder::new()
        .policies(vec![policy::op::eq(".args.foo", json!(42)), policy::op::eq("$.req.bar", json!(1337))])
        .subject(subject_did)
        .audience(subject_did)
        .command(["nil"])
        .sign(&*root_signer)
        .await
        .expect("failed to build root");

    // Intermediate delegation with additional policy
    let intermediate = DelegationBuilder::extending(root)
        .expect("failed to extend")
        .policy(policy::op::eq(".args.bar", json!(1337)))
        .audience(invocation_did)
        .command(["nil", "bar"])
        .sign(&*subject_signer)
        .await
        .expect("failed to build intermediate");

    // Invocation with arguments meeting all policies
    let invocation = InvocationBuilder::extending(intermediate)
        .arguments(json!({"foo": 42, "bar": 1337}))
        .audience(rpc_did)
        .command(["nil", "bar", "foo"])
        .sign(&*invocation_signer)
        .await
        .expect("failed to build invocation");

    let parameters =
        ValidationParameters { token_requirements: TokenTypeRequirements::Invocation(rpc_did), ..Default::default() };
    let context = HashMap::from([("req", json!({"bar": 1337}))]);
    let ValidatedNucToken { token, proofs } =
        Asserter::new(parameters).with_context(context).assert_success(invocation.unvalidate());

    assert_eq!(token.issuer, invocation_did);

    // Ensure the order is right
    assert_eq!(proofs[0].issuer, subject_did);
    assert_eq!(proofs[1].issuer, *ROOT_SIGNER.did());
}

#[tokio::test]
async fn valid_revocation_token() {
    let rpc_did = Did::key([0xaa; 33]);

    let invocation = build_invocation_with_one_proof(
        |delegation| delegation.policy(policy::op::eq(".args.foo", json!(42))),
        |invocation| {
            invocation.arguments(json!({ "foo": 42, "bar": 1337 })).audience(rpc_did).command(["nuc", "revoke"])
        },
    )
    .await;

    let parameters =
        ValidationParameters { token_requirements: TokenTypeRequirements::Invocation(rpc_did), ..Default::default() };
    Asserter::new(parameters).assert_success(invocation.unvalidate());
}

#[tokio::test]
async fn valid_no_root_keys_needed() {
    let subject_signer = signer();
    let subject_did = *subject_signer.did();

    // Self-signed delegation
    let delegation = DelegationBuilder::new()
        .subject(subject_did)
        .audience(subject_did)
        .command(["nil"])
        .sign(&*subject_signer)
        .await
        .expect("failed to build");

    let asserter = Asserter { root_keys: Vec::new(), ..Default::default() };
    asserter.assert_success(delegation.unvalidate());
}

#[tokio::test]
async fn valid_root_token() {
    let root_signer = root_signer();
    let subject_did = signer().did().clone();

    let delegation = delegation(subject_did).command(["nil"]).sign(&*root_signer).await.expect("failed to build");

    Asserter::default().assert_success(delegation.unvalidate());
}
