use super::*;
use crate::{
    builder::{DelegationBuilder, InvocationBuilder, NucTokenBuildError, to_base64},
    did::Did,
    envelope::from_base64,
    keypair::Keypair,
    policy,
    signer::{DidMethod, Secp256k1Signer},
    validator::policy::PolicyTreeProperties,
};
use rstest::rstest;
use serde::Serialize;
use serde_json::json;
use serde_with::{DisplayFromStr, serde_as};
use std::{env, sync::LazyLock};

static ROOT_KEYPAIR: LazyLock<Keypair> = LazyLock::new(Keypair::generate);
static ROOT_PUBLIC_KEYS: LazyLock<Vec<PublicKey>> = LazyLock::new(|| {
    let key = ROOT_KEYPAIR.public_key();
    vec![PublicKey::from_sec1_bytes(&key).expect("valid public key")]
});

enum TimeConfig {
    System,
    Mock(DateTime<Utc>),
}

struct MockTimeProvider(DateTime<Utc>);

impl TimeProvider for MockTimeProvider {
    fn current_time(&self) -> DateTime<Utc> {
        self.0
    }
}

struct Asserter {
    parameters: ValidationParameters,
    root_keys: Vec<PublicKey>,
    context: HashMap<&'static str, serde_json::Value>,
    time_config: TimeConfig,
    log_assertions: bool,
}

impl Asserter {
    fn new(parameters: ValidationParameters) -> Self {
        Self {
            parameters,
            root_keys: ROOT_PUBLIC_KEYS.clone(),
            context: Default::default(),
            time_config: TimeConfig::System,
            log_assertions: env::var("NUC_VALIDATOR_LOG_ASSERTIONS") == Ok("1".to_string()),
        }
    }

    fn with_context(mut self, context: HashMap<&'static str, serde_json::Value>) -> Self {
        self.context = context;
        self
    }

    fn with_current_time(mut self, time: DateTime<Utc>) -> Self {
        self.time_config = TimeConfig::Mock(time);
        self
    }

    fn into_assertion(self, envelope: &NucTokenEnvelope, expectation: AssertionExpectation) -> Assertion {
        let token = envelope.encode();
        let current_time = match self.time_config {
            TimeConfig::System => Utc::now(),
            TimeConfig::Mock(time) => time,
        };
        let root_keys = self.root_keys.iter().map(|k| hex::encode(k.to_sec1_bytes())).collect();
        let input =
            AssertionInput { token, current_time, root_keys, context: self.context, parameters: self.parameters };
        Assertion { input, expectation }
    }

    fn assert_failure<E: Into<ValidationError>>(self, envelope: NucTokenEnvelope, expected_failure: E) {
        let log = self.log_assertions;
        let ValidationError::Validation(kind) = expected_failure.into() else {
            panic!("unexpected error type");
        };
        let assertion = self.into_assertion(&envelope, AssertionExpectation::Failure { kind });
        assertion.validate(log).expect_err("no error");
    }

    fn assert_success(self, envelope: NucTokenEnvelope) -> ValidatedNucToken {
        let log = self.log_assertions;
        let assertion = self.into_assertion(&envelope, AssertionExpectation::Success);
        assertion.validate(log).expect("validation failed")
    }
}

#[derive(Serialize)]
struct Assertion {
    input: AssertionInput,
    expectation: AssertionExpectation,
}

impl Assertion {
    fn log_tokens(envelope: &NucTokenEnvelope) {
        // Log this so we can debug tests based on their output
        println!("Token being asserted: {}", serde_json::to_string_pretty(envelope.token().token()).unwrap());
        println!(
            "Proofs for it: {}",
            serde_json::to_string_pretty(&envelope.proofs().iter().map(|d| &d.token).collect::<Vec<_>>()).unwrap()
        );
    }

    fn validate(self, log: bool) -> Result<ValidatedNucToken, ValidationError> {
        if log {
            eprintln!("{}", serde_json::to_string(&self).expect("serialization failed"));
        }
        let Assertion { input, expectation } = self;
        let envelope = NucTokenEnvelope::decode(&input.token).expect("malformed token");
        Self::log_tokens(&envelope);

        let root_keys: Vec<_> = input
            .root_keys
            .iter()
            .map(|k| PublicKey::from_sec1_bytes(&hex::decode(k).expect("invalid hex")).expect("invalid root key"))
            .collect();
        let mut validator = NucValidator::new(&root_keys);
        validator.time_provider = Box::new(MockTimeProvider(input.current_time));
        let result = validator.validate(envelope, input.parameters, &input.context);
        match (result, expectation) {
            (Ok(token), AssertionExpectation::Success) => Ok(token),
            (Ok(_), _) => panic!("validation failed"),
            (Err(e), AssertionExpectation::Success) => panic!("expected success, got failure: {e}"),
            (Err(e), AssertionExpectation::Failure { kind }) => {
                match e {
                    ValidationError::Validation(e) => {
                        if e != kind {
                            panic!("unexpected type of failure: {e}");
                        }
                    }
                    ValidationError::Serde(_) => {
                        panic!("unexpected type of failure");
                    }
                }
                Err(e)
            }
        }
    }
}

#[derive(Serialize)]
struct AssertionInput {
    token: String,
    root_keys: Vec<String>,
    #[serde(with = "chrono::serde::ts_seconds")]
    current_time: DateTime<Utc>,
    context: HashMap<&'static str, serde_json::Value>,
    parameters: ValidationParameters,
}

#[serde_as]
#[derive(Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
enum AssertionExpectation {
    Success,
    Failure {
        #[serde_as(as = "DisplayFromStr")]
        kind: ValidationKind,
    },
}

impl Default for Asserter {
    fn default() -> Self {
        let parameters = ValidationParameters::default();
        Self::new(parameters)
    }
}

fn keypair() -> Keypair {
    Keypair::generate()
}

fn root_signer() -> Secp256k1Signer {
    ROOT_KEYPAIR.signer(DidMethod::Key)
}

// Create a delegation with the most common fields already set so we don't need to deal
// with them in every single test.
fn delegation(subject: &Keypair) -> DelegationBuilder {
    DelegationBuilder::new().audience(Did::key([0xde; 33])).subject(subject.to_did(DidMethod::Key))
}

// Same as the above but for invocations
#[allow(dead_code)]
fn invocation(subject: &Keypair) -> InvocationBuilder {
    InvocationBuilder::new().audience(Did::key([0xde; 33])).subject(subject.to_did(DidMethod::Key))
}

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
