use super::fixtures::*;
use crate::{builder::DelegationBuilder, did::Did, signer::DidMethod, validator::error::ValidationKind};
use chrono::DateTime;

#[tokio::test]
async fn root_token_expired() {
    let now = DateTime::from_timestamp(10, 0).unwrap();
    let expires_at = DateTime::from_timestamp(5, 0).unwrap();

    let key = keypair();
    let root_signer = root_signer();
    let key_signer = key.signer(DidMethod::Key);

    // First token with expiration in the past
    let first = delegation(&key)
        .command(["nil"])
        .expires_at(expires_at)
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

    Asserter::default().with_current_time(now).assert_failure(second.unvalidate(), ValidationKind::TokenExpired);
}

#[tokio::test]
async fn last_token_expired() {
    let now = DateTime::from_timestamp(10, 0).unwrap();
    let expires_at = DateTime::from_timestamp(5, 0).unwrap();

    let key = keypair();
    let root_signer = root_signer();
    let key_signer = key.signer(DidMethod::Key);

    let first = delegation(&key)
        .command(["nil"])
        .audience(key.to_did(DidMethod::Key))
        .sign(&root_signer)
        .await
        .expect("failed to build first");

    // Second token with expiration in the past
    let second = DelegationBuilder::extending(first)
        .expect("failed to extend")
        .audience(Did::key([0xde; 33]))
        .command(["nil"])
        .expires_at(expires_at)
        .sign(&key_signer)
        .await
        .expect("failed to build second");

    Asserter::default().with_current_time(now).assert_failure(second.unvalidate(), ValidationKind::TokenExpired);
}

#[tokio::test]
async fn proof_not_before_not_met() {
    let now = DateTime::from_timestamp(0, 0).unwrap();
    let not_before = DateTime::from_timestamp(10, 0).unwrap();

    let key = keypair();
    let root_signer = root_signer();
    let key_signer = key.signer(DidMethod::Key);

    // First token with not_before in the future
    let first = delegation(&key)
        .command(["nil"])
        .not_before(not_before)
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

    Asserter::default().with_current_time(now).assert_failure(second.unvalidate(), ValidationKind::NotBeforeNotMet);
}

#[tokio::test]
async fn last_not_before_not_met() {
    let now = DateTime::from_timestamp(0, 0).unwrap();
    let not_before = DateTime::from_timestamp(10, 0).unwrap();

    let key = keypair();
    let root_signer = root_signer();
    let key_signer = key.signer(DidMethod::Key);

    let first = delegation(&key)
        .command(["nil"])
        .audience(key.to_did(DidMethod::Key))
        .sign(&root_signer)
        .await
        .expect("failed to build first");

    // Second token with not_before in the future
    let second = DelegationBuilder::extending(first)
        .expect("failed to extend")
        .audience(Did::key([0xde; 33]))
        .command(["nil"])
        .not_before(not_before)
        .sign(&key_signer)
        .await
        .expect("failed to build second");

    Asserter::default().with_current_time(now).assert_failure(second.unvalidate(), ValidationKind::NotBeforeNotMet);
}

#[tokio::test]
async fn not_before_backwards() {
    let now = DateTime::from_timestamp(0, 0).unwrap();
    let root_not_before = DateTime::from_timestamp(5, 0).unwrap();
    let last_not_before = DateTime::from_timestamp(3, 0).unwrap();

    let key = keypair();
    let root_signer = root_signer();
    let key_signer = key.signer(DidMethod::Key);

    // First token with not_before = 5
    let first = delegation(&key)
        .command(["nil"])
        .not_before(root_not_before)
        .audience(key.to_did(DidMethod::Key))
        .sign(&root_signer)
        .await
        .expect("failed to build first");

    // Second token with not_before = 3 (backwards)
    let second = DelegationBuilder::extending(first)
        .expect("failed to extend")
        .audience(Did::key([0xde; 33]))
        .command(["nil"])
        .not_before(last_not_before)
        .sign(&key_signer)
        .await
        .expect("failed to build second");

    Asserter::default().with_current_time(now).assert_failure(second.unvalidate(), ValidationKind::NotBeforeBackwards);
}
