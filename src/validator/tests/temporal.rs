use super::fixtures::*;
use crate::validator::error::ValidationKind;
use chrono::DateTime;

#[tokio::test]
async fn root_token_expired() {
    let now = DateTime::from_timestamp(10, 0).unwrap();
    let expires_at = DateTime::from_timestamp(5, 0).unwrap();

    let chain = build_two_link_delegation_chain(
        |root| root.expires_at(expires_at),
        |second| second, // No change to the second token
    )
    .await;

    Asserter::default().with_current_time(now).assert_failure(chain.unvalidate(), ValidationKind::TokenExpired);
}

#[tokio::test]
async fn last_token_expired() {
    let now = DateTime::from_timestamp(10, 0).unwrap();
    let expires_at = DateTime::from_timestamp(5, 0).unwrap();

    let chain = build_two_link_delegation_chain(
        |root| root, // No change to the root token
        |second| second.expires_at(expires_at),
    )
    .await;

    Asserter::default().with_current_time(now).assert_failure(chain.unvalidate(), ValidationKind::TokenExpired);
}

#[tokio::test]
async fn proof_not_before_not_met() {
    let now = DateTime::from_timestamp(0, 0).unwrap();
    let not_before = DateTime::from_timestamp(10, 0).unwrap();

    let chain = build_two_link_delegation_chain(|root| root.not_before(not_before), |second| second).await;

    Asserter::default().with_current_time(now).assert_failure(chain.unvalidate(), ValidationKind::NotBeforeNotMet);
}

#[tokio::test]
async fn last_not_before_not_met() {
    let now = DateTime::from_timestamp(0, 0).unwrap();
    let not_before = DateTime::from_timestamp(10, 0).unwrap();

    let chain = build_two_link_delegation_chain(|root| root, |second| second.not_before(not_before)).await;

    Asserter::default().with_current_time(now).assert_failure(chain.unvalidate(), ValidationKind::NotBeforeNotMet);
}

#[tokio::test]
async fn not_before_backwards() {
    let now = DateTime::from_timestamp(0, 0).unwrap();
    let root_not_before = DateTime::from_timestamp(5, 0).unwrap();
    let last_not_before = DateTime::from_timestamp(3, 0).unwrap();

    let chain = build_two_link_delegation_chain(
        |root| root.not_before(root_not_before),
        |second| second.not_before(last_not_before),
    )
    .await;

    Asserter::default().with_current_time(now).assert_failure(chain.unvalidate(), ValidationKind::NotBeforeBackwards);
}
