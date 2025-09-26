use super::fixtures::*;
use crate::{
    builder::{DelegationBuilder, InvocationBuilder, NucTokenBuildError, to_base64},
    did::Did,
    envelope::{NucTokenEnvelope, from_base64},
    policy,
    signer::DidMethod,
    validator::{TokenTypeRequirements, ValidatedNucToken, ValidationParameters, error::ValidationKind},
};
use serde_json::json;
use std::collections::HashMap;

#[tokio::test]
async fn unlinked_chain() {
    let key = keypair();
    let root_signer = root_signer();
    let key_signer = key.signer(DidMethod::Key);

    // Build the first delegation token
    let first = delegation(&key)
        .command(["nil"])
        .audience(key.to_did(DidMethod::Key))
        .sign(&root_signer)
        .await
        .expect("failed to build first");

    // Build the second token extending the first
    let second = DelegationBuilder::extending(first.clone())
        .expect("failed to extend")
        .audience(Did::key([0xde; 33]))
        .command(["nil"])
        .sign(&key_signer)
        .await
        .expect("failed to build second");

    // Now add an unlinked token (not chained properly)
    let unlinked =
        delegation(&key).command(["nil"]).sign_and_serialize(&root_signer).await.expect("failed to build unlinked");

    // Manually construct an envelope with the unlinked proof
    let second_encoded = second.unvalidate().encode();
    let token = format!("{}/{}", second_encoded, unlinked);
    let envelope = NucTokenEnvelope::decode(&token).expect("decode failed");
    Asserter::default().assert_failure(envelope, ValidationKind::UnchainedProofs);
}

#[tokio::test]
async fn chain_too_long() {
    let key = keypair();
    let root_signer = root_signer();
    let key_signer = key.signer(DidMethod::Key);

    // Build first token
    let first = delegation(&key)
        .command(["nil"])
        .audience(key.to_did(DidMethod::Key))
        .sign(&root_signer)
        .await
        .expect("failed to build first");

    // Build second token extending first
    let second = DelegationBuilder::extending(first)
        .expect("failed to extend")
        .audience(key.to_did(DidMethod::Key))
        .command(["nil"])
        .sign(&key_signer)
        .await
        .expect("failed to build second");

    // Build third token extending second
    let third = DelegationBuilder::extending(second)
        .expect("failed to extend")
        .audience(Did::key([0xde; 33]))
        .command(["nil"])
        .sign(&key_signer)
        .await
        .expect("failed to build third");

    let parameters = ValidationParameters { max_chain_length: 2, ..Default::default() };
    Asserter::new(parameters).assert_failure(third.unvalidate(), ValidationKind::ChainTooLong);
}

#[tokio::test]
async fn command_not_attenuated() {
    let key = keypair();
    let root_signer = root_signer();
    let key_signer = key.signer(DidMethod::Key);

    // Root delegation with "nil" command
    let first = delegation(&key)
        .command(["nil"])
        .audience(key.to_did(DidMethod::Key))
        .sign(&root_signer)
        .await
        .expect("failed to build first");

    // Second delegation with "bar" command (not an attenuation of "nil")
    let second = DelegationBuilder::extending(first)
        .expect("failed to extend")
        .audience(Did::key([0xde; 33]))
        .command(["bar"])
        .sign(&key_signer)
        .await
        .expect("failed to build second");

    Asserter::default().assert_failure(second.unvalidate(), ValidationKind::CommandNotAttenuated);
}

#[tokio::test]
async fn issuer_audience_mismatch() {
    let key = keypair();
    let root_signer = root_signer();
    let key_signer = key.signer(DidMethod::Key);

    // First delegation with an audience that does not match the next issuer
    let first = delegation(&key)
        .command(["nil"])
        .audience(Did::key([0xaa; 33])) // Mismatched audience
        .sign(&root_signer)
        .await
        .expect("failed to build first");

    // Second delegation extends the first. The builder ensures its issuer (`key_signer`)
    // must match the first token's audience. Since it doesn't, validation will fail.
    let second = DelegationBuilder::extending(first)
        .expect("failed to extend")
        .audience(Did::key([0xde; 33])) // This audience doesn't matter for the test
        .sign(&key_signer)
        .await
        .expect("failed to build second");

    Asserter::default().assert_failure(second.unvalidate(), ValidationKind::IssuerAudienceMismatch);
}

#[tokio::test]
async fn invalid_audience_invocation() {
    let key = keypair();
    let root_signer = root_signer();
    let key_signer = key.signer(DidMethod::Key);

    let expected_did = Did::key([0xaa; 33]);
    let actual_did = Did::key([0xbb; 33]);

    // Build delegation
    let first = delegation(&key)
        .command(["nil"])
        .audience(key.to_did(DidMethod::Key))
        .sign(&root_signer)
        .await
        .expect("failed to build delegation");

    // Build invocation with wrong audience
    let second = InvocationBuilder::extending(first)
        .command(["nil"])
        .audience(actual_did)
        .sign(&key_signer)
        .await
        .expect("failed to build invocation");

    let parameters = ValidationParameters {
        token_requirements: TokenTypeRequirements::Invocation(expected_did),
        ..Default::default()
    };
    Asserter::new(parameters).assert_failure(second.unvalidate(), ValidationKind::InvalidAudience);
}

#[tokio::test]
async fn invalid_signature() {
    let key = keypair();
    let root_signer = root_signer();

    let envelope = delegation(&key).command(["nil"]).sign(&root_signer).await.expect("failed to build");

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
    let key = keypair();
    let root_signer = root_signer();
    let key_signer = key.signer(DidMethod::Key);

    let expected_did = Did::key([0xaa; 33]);
    let actual_did = Did::key([0xbb; 33]);

    // Build first delegation
    let first = delegation(&key)
        .command(["nil"])
        .audience(key.to_did(DidMethod::Key))
        .sign(&root_signer)
        .await
        .expect("failed to build first");

    // Build second delegation with wrong audience
    let second = DelegationBuilder::extending(first)
        .expect("failed to extend")
        .command(["nil"])
        .audience(actual_did)
        .sign(&key_signer)
        .await
        .expect("failed to build second");

    let parameters = ValidationParameters {
        token_requirements: TokenTypeRequirements::Delegation(expected_did),
        ..Default::default()
    };
    Asserter::new(parameters).assert_failure(second.unvalidate(), ValidationKind::InvalidAudience);
}

#[tokio::test]
async fn missing_proof() {
    let key = keypair();
    let root_signer = root_signer();
    let key_signer = key.signer(DidMethod::Key);

    // Build chain
    let first = delegation(&key)
        .command(["nil"])
        .audience(key.to_did(DidMethod::Key))
        .sign(&root_signer)
        .await
        .expect("failed to build first");

    let second = DelegationBuilder::extending(first)
        .expect("failed to extend")
        .audience(Did::key([0xde; 33]))
        .command(["nil"])
        .sign(&key_signer)
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
    let key = keypair();
    let root_signer = root_signer();
    let key_signer = key.signer(DidMethod::Key);

    // Build delegation then invocation
    let first = delegation(&key)
        .command(["nil"])
        .audience(key.to_did(DidMethod::Key))
        .sign(&root_signer)
        .await
        .expect("failed to build delegation");

    let second = InvocationBuilder::extending(first)
        .command(["nil"])
        .audience(Did::key([0xde; 33]))
        .sign(&key_signer)
        .await
        .expect("failed to build invocation");

    let parameters = ValidationParameters {
        token_requirements: TokenTypeRequirements::Delegation(Did::key([0xaa; 33])),
        ..Default::default()
    };
    Asserter::new(parameters).assert_failure(second.unvalidate(), ValidationKind::NeedDelegation);
}

#[tokio::test]
async fn need_invocation() {
    let key = keypair();
    let root_signer = root_signer();
    let key_signer = key.signer(DidMethod::Key);

    // Build delegation chain
    let first = delegation(&key)
        .command(["nil"])
        .audience(key.to_did(DidMethod::Key))
        .sign(&root_signer)
        .await
        .expect("failed to build first");

    let second = DelegationBuilder::extending(first)
        .expect("failed to extend")
        .audience(Did::key([0xde; 33]))
        .command(["nil"])
        .sign(&key_signer)
        .await
        .expect("failed to build second");

    let parameters = ValidationParameters {
        token_requirements: TokenTypeRequirements::Invocation(Did::key([0xaa; 33])),
        ..Default::default()
    };
    Asserter::new(parameters).assert_failure(second.unvalidate(), ValidationKind::NeedInvocation);
}

#[tokio::test]
async fn proofs_must_be_delegations() {
    let key = keypair();
    let root_signer = root_signer();
    let subject = key.to_did(DidMethod::Key);

    // Root is an invocation
    let root_invocation = InvocationBuilder::new()
        .arguments(json!({"bar": 1337}))
        .subject(subject.clone())
        .audience(key.to_did(DidMethod::Key))
        .command(["nil"])
        .sign(&root_signer)
        .await
        .expect("failed to build root invocation");

    // Attempting to create a delegation from an invocation proof should fail.
    let result = DelegationBuilder::extending(root_invocation);

    assert!(matches!(result, Err(NucTokenBuildError::CannotExtendInvocation)));
}

#[tokio::test]
async fn root_key_signature_missing() {
    let key = keypair();
    let key_signer = key.signer(DidMethod::Key);

    // First delegation signed by non-root key
    let first = delegation(&key)
        .command(["nil"])
        .audience(key.to_did(DidMethod::Key))
        .sign(&key_signer)
        .await
        .expect("failed to build first");

    // Second delegation
    let second = DelegationBuilder::extending(first)
        .expect("failed to extend")
        .audience(Did::key([0xde; 33]))
        .command(["nil"])
        .sign(&key_signer)
        .await
        .expect("failed to build second");

    Asserter::default().assert_failure(second.unvalidate(), ValidationKind::RootKeySignatureMissing);
}

#[tokio::test]
async fn subject_not_in_chain() {
    let subject_key = keypair();
    let other_key = keypair();
    let root_signer = root_signer();
    let other_signer = other_key.signer(DidMethod::Key);

    // Root delegation with subject_key as subject
    let first = delegation(&subject_key)
        .command(["nil"])
        .audience(other_key.to_did(DidMethod::Key))
        .sign(&root_signer)
        .await
        .expect("failed to build first");

    // Second delegation signed by other_key (not subject_key)
    let second = DelegationBuilder::extending(first)
        .expect("failed to extend")
        .audience(Did::key([0xde; 33]))
        .command(["nil"])
        .sign(&other_signer)
        .await
        .expect("failed to build second");

    Asserter::default().assert_failure(second.unvalidate(), ValidationKind::SubjectNotInChain);
}

#[tokio::test]
async fn valid_token() {
    let subject_key = keypair();
    let invocation_key = keypair();
    let root_signer = root_signer();
    let subject_signer = subject_key.signer(DidMethod::Key);
    let invocation_signer = invocation_key.signer(DidMethod::Key);
    let subject = subject_key.to_did(DidMethod::Key);
    let rpc_did = Did::key([0xaa; 33]);

    // Root delegation with policies
    let root = DelegationBuilder::new()
        .policies(vec![policy::op::eq(".args.foo", json!(42)), policy::op::eq("$.req.bar", json!(1337))])
        .subject(subject.clone())
        .audience(subject.clone())
        .command(["nil"])
        .sign(&root_signer)
        .await
        .expect("failed to build root");

    // Intermediate delegation with additional policy
    let intermediate = DelegationBuilder::extending(root)
        .expect("failed to extend")
        .policy(policy::op::eq(".args.bar", json!(1337)))
        .audience(invocation_key.to_did(DidMethod::Key))
        .command(["nil", "bar"])
        .sign(&subject_signer)
        .await
        .expect("failed to build intermediate");

    // Invocation with arguments meeting all policies
    let invocation = InvocationBuilder::extending(intermediate)
        .arguments(json!({"foo": 42, "bar": 1337}))
        .audience(rpc_did.clone())
        .command(["nil", "bar", "foo"])
        .sign(&invocation_signer)
        .await
        .expect("failed to build invocation");

    let parameters =
        ValidationParameters { token_requirements: TokenTypeRequirements::Invocation(rpc_did), ..Default::default() };
    let context = HashMap::from([("req", json!({"bar": 1337}))]);
    let ValidatedNucToken { token, proofs } =
        Asserter::new(parameters).with_context(context).assert_success(invocation.unvalidate());

    assert_eq!(token.issuer, invocation_key.to_did(DidMethod::Key));

    // Ensure the order is right
    assert_eq!(proofs[0].issuer, subject);
    assert_eq!(proofs[1].issuer, ROOT_KEYPAIR.to_did(DidMethod::Key));
}

#[tokio::test]
async fn valid_revocation_token() {
    let subject_key = keypair();
    let root_signer = root_signer();
    let subject_signer = subject_key.signer(DidMethod::Key);
    let subject = subject_key.to_did(DidMethod::Key);
    let rpc_did = Did::key([0xaa; 33]);

    // Root delegation with policy
    let root = DelegationBuilder::new()
        .policy(policy::op::eq(".args.foo", json!(42)))
        .subject(subject.clone())
        .audience(subject.clone())
        .command(["nil"])
        .sign(&root_signer)
        .await
        .expect("failed to build root");

    // Revocation invocation
    let invocation = InvocationBuilder::extending(root)
        .arguments(json!({"foo": 42, "bar": 1337}))
        .audience(rpc_did.clone())
        .command(["nuc", "revoke"])
        .sign(&subject_signer)
        .await
        .expect("failed to build invocation");

    let parameters =
        ValidationParameters { token_requirements: TokenTypeRequirements::Invocation(rpc_did), ..Default::default() };
    Asserter::new(parameters).assert_success(invocation.unvalidate());
}

#[tokio::test]
async fn valid_no_root_keys_needed() {
    let subject_key = keypair();
    let subject_signer = subject_key.signer(DidMethod::Key);
    let subject = subject_key.to_did(DidMethod::Key);

    // Self-signed delegation
    let delegation = DelegationBuilder::new()
        .subject(subject.clone())
        .audience(subject)
        .command(["nil"])
        .sign(&subject_signer)
        .await
        .expect("failed to build");

    let asserter = Asserter { root_keys: Vec::new(), ..Default::default() };
    asserter.assert_success(delegation.unvalidate());
}

#[tokio::test]
async fn valid_root_token() {
    let key = keypair();
    let root_signer = root_signer();

    let delegation = delegation(&key).command(["nil"]).sign(&root_signer).await.expect("failed to build");

    Asserter::default().assert_success(delegation.unvalidate());
}
