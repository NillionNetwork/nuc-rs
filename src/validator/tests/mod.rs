use super::*;
use crate::{
    builder::{NucTokenBuilder, to_base64},
    did::Did,
    envelope::from_base64,
    policy,
    signer::{DidMethod, Secp256k1Signer},
    validator::policy::PolicyTreeProperties,
};
use k256::SecretKey;
use rstest::rstest;
use serde::Serialize;
use serde_json::json;
use serde_with::{DisplayFromStr, serde_as};
use std::{env, ops::Deref, sync::LazyLock};

static ROOT_SECRET_KEYS: LazyLock<Vec<SecretKey>> = LazyLock::new(|| vec![SecretKey::random(&mut rand::thread_rng())]);
static ROOT_PUBLIC_KEYS: LazyLock<Vec<PublicKey>> =
    LazyLock::new(|| ROOT_SECRET_KEYS.iter().map(|s| s.public_key()).collect());

// A helper to chain tokens together.
struct Chainer {
    chain_issuer_audience: bool,
}

impl Default for Chainer {
    fn default() -> Self {
        Self { chain_issuer_audience: true }
    }
}

impl Chainer {
    async fn chain<const N: usize>(&self, mut builders: [Builder; N]) -> NucTokenEnvelope {
        if self.chain_issuer_audience {
            // Chain the issuer -> audience in every token
            for i in 0..builders.len().saturating_sub(1) {
                let next = &builders[i + 1];
                let issuer_key: [u8; 33] = next.owner_key.public_key().to_sec1_bytes().deref().try_into().unwrap();

                let previous = &mut builders[i];
                previous.builder = previous.builder.clone().audience(Did::key(issuer_key));
            }
        }

        // Now chain the proof hashes
        let mut builders = builders.into_iter();
        let token = builders.next().expect("no builders").build().await;
        let mut envelope = NucTokenEnvelope::decode(&token).unwrap();
        for mut builder in builders {
            let next = envelope.validate_signatures().expect("signature validation failed");
            builder.builder = builder.builder.proof(next);

            let token = builder.build().await;
            envelope = NucTokenEnvelope::decode(&token).unwrap();
        }
        envelope
    }
}

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

struct Builder {
    builder: NucTokenBuilder,
    owner_key: SecretKey,
}

impl Builder {
    async fn build(self) -> String {
        let signer = Secp256k1Signer::new(self.owner_key.into(), DidMethod::Key);
        self.builder.build(&signer).await.expect("failed to build")
    }
}

trait NucTokenBuilderExt: Sized {
    fn issued_by_root(self) -> Builder;
    fn issued_by(self, owner_key: SecretKey) -> Builder;
}

impl NucTokenBuilderExt for NucTokenBuilder {
    fn issued_by_root(self) -> Builder {
        Builder { builder: self, owner_key: ROOT_SECRET_KEYS[0].clone() }
    }

    fn issued_by(self, owner_key: SecretKey) -> Builder {
        Builder { builder: self, owner_key }
    }
}

fn secret_key() -> SecretKey {
    SecretKey::random(&mut rand::thread_rng())
}

// Create a delegation with the most common fields already set so we don't need to deal
// with them in every single test.
fn delegation(subject: &SecretKey) -> NucTokenBuilder {
    let subject_pk: [u8; 33] = subject.public_key().to_sec1_bytes().as_ref().try_into().unwrap();
    NucTokenBuilder::delegation([]).audience(Did::key([0xde; 33])).subject(Did::key(subject_pk))
}

// Same as the above but for invocations
fn invocation(subject: &SecretKey) -> NucTokenBuilder {
    let subject_pk: [u8; 33] = subject.public_key().to_sec1_bytes().as_ref().try_into().unwrap();
    NucTokenBuilder::invocation(Default::default()).audience(Did::key([0xde; 33])).subject(Did::key(subject_pk))
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
    let key = secret_key();
    let base = delegation(&key).command(["nil"]);
    // Chain 2.
    let envelope =
        Chainer::default().chain([base.clone().issued_by_root(), base.clone().issued_by(key)]).await.encode();

    // Now chain an extra one that nobody refers to.
    let last = base.clone().issued_by_root().build().await;
    let token = format!("{envelope}/{last}");
    let envelope = NucTokenEnvelope::decode(&token).expect("decode failed");
    Asserter::default().assert_failure(envelope, ValidationKind::UnchainedProofs);
}

#[tokio::test]
async fn chain_too_long() {
    let key = secret_key();
    let base = delegation(&key).command(["nil"]);
    let last = base.clone();
    let envelope = Chainer::default()
        .chain([base.clone().issued_by_root(), base.clone().issued_by(key.clone()), last.issued_by(key.clone())])
        .await;
    let parameters = ValidationParameters { max_chain_length: 2, ..Default::default() };
    Asserter::new(parameters).assert_failure(envelope, ValidationKind::ChainTooLong);
}

#[tokio::test]
async fn command_not_attenuated() {
    let key = secret_key();
    let base = delegation(&key);
    let root = base.clone().command(["nil"]).issued_by_root();
    let last = base.command(["bar"]).issued_by(key);
    let envelope = Chainer::default().chain([root, last]).await;
    Asserter::default().assert_failure(envelope, ValidationKind::CommandNotAttenuated);
}

#[tokio::test]
async fn different_subjects() {
    let key1 = secret_key();
    let mut key2_bytes = key1.to_bytes();
    key2_bytes[0] ^= 1;
    let key2 = SecretKey::from_bytes(&key2_bytes).unwrap();

    let root = delegation(&key1).command(["nil"]).issued_by_root();
    let last = delegation(&key2).command(["nil"]).issued_by(key2);
    let envelope = Chainer::default().chain([root, last]).await;
    Asserter::default().assert_failure(envelope, ValidationKind::DifferentSubjects);
}

#[tokio::test]
async fn issuer_audience_mismatch() {
    let key = secret_key();
    let base = delegation(&key).command(["nil"]);
    let root = base.clone().audience(Did::key([0xaa; 33])).issued_by_root();
    let last = base.issued_by(key);
    let envelope = Chainer { chain_issuer_audience: false }.chain([root, last]).await;
    Asserter::default().assert_failure(envelope, ValidationKind::IssuerAudienceMismatch);
}

#[tokio::test]
async fn invalid_audience_invocation() {
    let key = secret_key();
    let expected_did = Did::key([0xaa; 33]);
    let actual_did = Did::key([0xbb; 33]);
    let root = delegation(&key).command(["nil"]).issued_by_root();
    let last = invocation(&key).command(["nil"]).audience(actual_did).issued_by(key);
    let envelope = Chainer::default().chain([root, last]).await;
    let parameters = ValidationParameters {
        token_requirements: TokenTypeRequirements::Invocation(expected_did),
        ..Default::default()
    };
    Asserter::new(parameters).assert_failure(envelope, ValidationKind::InvalidAudience);
}

#[tokio::test]
async fn invalid_signature() {
    let key = secret_key();
    let root = delegation(&key).command(["nil"]).issued_by_root();
    let token = Chainer::default().chain([root]).await.encode();
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
    let key = secret_key();
    let expected_did = Did::key([0xaa; 33]);
    let actual_did = Did::key([0xbb; 33]);
    let root = delegation(&key).command(["nil"]).issued_by_root();
    let last = delegation(&key).command(["nil"]).audience(actual_did).issued_by(key);
    let envelope = Chainer::default().chain([root, last]).await;
    let parameters = ValidationParameters {
        token_requirements: TokenTypeRequirements::Delegation(expected_did),
        ..Default::default()
    };
    Asserter::new(parameters).assert_failure(envelope, ValidationKind::InvalidAudience);
}

#[tokio::test]
async fn missing_proof() {
    let key = secret_key();
    let base = delegation(&key).command(["nil"]);
    let token = Chainer::default().chain([base.clone().issued_by_root(), base.clone().issued_by(key)]).await.encode();
    // Keep the token without its proof
    let token = token.split_once("/").unwrap().0;
    let envelope = NucTokenEnvelope::decode(token).expect("invalid token");
    Asserter::default().assert_failure(envelope, ValidationKind::MissingProof);
}

#[tokio::test]
async fn need_delegation() {
    let key = secret_key();
    let root = delegation(&key).command(["nil"]).issued_by_root();
    let last = invocation(&key).command(["nil"]).issued_by(key);
    let envelope = Chainer::default().chain([root, last]).await;
    let parameters = ValidationParameters {
        token_requirements: TokenTypeRequirements::Delegation(Did::key([0xaa; 33])),
        ..Default::default()
    };
    Asserter::new(parameters).assert_failure(envelope, ValidationKind::NeedDelegation);
}

#[tokio::test]
async fn need_invocation() {
    let key = secret_key();
    let base = delegation(&key).command(["nil"]);
    let root = base.clone().issued_by_root();
    let last = base.issued_by(key);
    let envelope = Chainer::default().chain([root, last]).await;
    let parameters = ValidationParameters {
        token_requirements: TokenTypeRequirements::Invocation(Did::key([0xaa; 33])),
        ..Default::default()
    };
    Asserter::new(parameters).assert_failure(envelope, ValidationKind::NeedInvocation);
}

#[tokio::test]
async fn not_before_backwards() {
    let now = DateTime::from_timestamp(0, 0).unwrap();
    let root_not_before = DateTime::from_timestamp(5, 0).unwrap();
    let last_not_before = DateTime::from_timestamp(3, 0).unwrap();

    let key = secret_key();
    let base = delegation(&key).command(["nil"]);
    let root = base.clone().not_before(root_not_before).issued_by_root();
    let last = base.not_before(last_not_before).issued_by(key);
    let envelope = Chainer::default().chain([root, last]).await;
    Asserter::default().with_current_time(now).assert_failure(envelope, ValidationKind::NotBeforeBackwards);
}

#[tokio::test]
async fn proof_not_before_not_met() {
    let now = DateTime::from_timestamp(0, 0).unwrap();
    let not_before = DateTime::from_timestamp(10, 0).unwrap();

    let key = secret_key();
    let base = delegation(&key).command(["nil"]);
    let root = base.clone().not_before(not_before).issued_by_root();
    let last = base.issued_by(key);
    let envelope = Chainer::default().chain([root, last]).await;
    Asserter::default().with_current_time(now).assert_failure(envelope, ValidationKind::NotBeforeNotMet);
}

#[tokio::test]
async fn last_not_before_not_met() {
    let now = DateTime::from_timestamp(0, 0).unwrap();
    let not_before = DateTime::from_timestamp(10, 0).unwrap();

    let key = secret_key();
    let base = delegation(&key).command(["nil"]);
    let root = base.clone().issued_by_root();
    let last = base.not_before(not_before).issued_by(key);
    let envelope = Chainer::default().chain([root, last]).await;
    Asserter::default().with_current_time(now).assert_failure(envelope, ValidationKind::NotBeforeNotMet);
}

#[tokio::test]
async fn root_policy_not_met() {
    let key = secret_key();
    let subject_pk: [u8; 33] = key.public_key().to_sec1_bytes().as_ref().try_into().unwrap();
    let subject = Did::key(subject_pk);
    let root = NucTokenBuilder::delegation([policy::op::eq(".foo", json!(42))])
        .subject(subject.clone())
        .command(["nil"])
        .issued_by_root();
    let invocation = NucTokenBuilder::invocation(json!({"bar": 1337}).as_object().cloned().unwrap())
        .subject(subject)
        .audience(Did::key([0xaa; 33]))
        .command(["nil"])
        .issued_by(key);

    let envelope = Chainer::default().chain([root, invocation]).await;
    Asserter::default().assert_failure(envelope, ValidationKind::PolicyNotMet);
}

#[tokio::test]
async fn last_policy_not_met() {
    let subject_key = secret_key();
    let subject_pk: [u8; 33] = subject_key.public_key().to_sec1_bytes().as_ref().try_into().unwrap();
    let subject = Did::key(subject_pk);
    let root = NucTokenBuilder::delegation([]).subject(subject.clone()).command(["nil"]).issued_by_root();
    let intermediate = NucTokenBuilder::delegation([policy::op::eq(".foo", json!(42))])
        .subject(subject.clone())
        .command(["nil"])
        .issued_by(subject_key);
    let invocation = NucTokenBuilder::invocation(json!({"bar": 1337}).as_object().cloned().unwrap())
        .subject(subject)
        .audience(Did::key([0xaa; 33]))
        .command(["nil"])
        .issued_by(secret_key());

    let envelope = Chainer::default().chain([root, intermediate, invocation]).await;
    Asserter::default().assert_failure(envelope, ValidationKind::PolicyNotMet);
}

#[tokio::test]
async fn policy_too_deep() {
    // Build a not(not(not...(op))) chain that's one too deep
    let mut policy = policy::op::eq(".foo", json!(42));
    for _ in 0..MAX_POLICY_DEPTH {
        policy = policy::op::not(policy);
    }
    let key = SecretKey::random(&mut rand::thread_rng());
    let subject_pk: [u8; 33] = key.public_key().to_sec1_bytes().as_ref().try_into().unwrap();
    let subject = Did::key(subject_pk);
    let root = NucTokenBuilder::delegation([policy]).subject(subject.clone()).command(["nil"]).issued_by_root();
    let tail = delegation(&key).command(["nil"]).issued_by(key);

    let envelope = Chainer::default().chain([root, tail]).await;
    Asserter::default().assert_failure(envelope, ValidationKind::PolicyTooDeep);
}

#[tokio::test]
async fn policy_array_too_wide() {
    let policy = vec![policy::op::eq(".foo", json!(42)); MAX_POLICY_WIDTH + 1];
    let key = SecretKey::random(&mut rand::thread_rng());
    let subject_pk: [u8; 33] = key.public_key().to_sec1_bytes().as_ref().try_into().unwrap();
    let subject = Did::key(subject_pk);
    let root = NucTokenBuilder::delegation(policy).subject(subject.clone()).command(["nil"]).issued_by_root();
    let tail = delegation(&key).command(["nil"]).issued_by(key);
    let envelope = Chainer::default().chain([root, tail]).await;
    Asserter::default().assert_failure(envelope, ValidationKind::PolicyTooWide);
}

#[tokio::test]
async fn policy_too_wide() {
    let policy = vec![policy::op::eq(".foo", json!(42)); MAX_POLICY_WIDTH + 1];
    let policy = policy::op::and(policy);
    let key = SecretKey::random(&mut rand::thread_rng());
    let subject_pk: [u8; 33] = key.public_key().to_sec1_bytes().as_ref().try_into().unwrap();
    let subject = Did::key(subject_pk);
    let root = NucTokenBuilder::delegation([policy]).subject(subject.clone()).command(["nil"]).issued_by_root();
    let tail = delegation(&key).command(["nil"]).issued_by(key);
    let envelope = Chainer::default().chain([root, tail]).await;
    Asserter::default().assert_failure(envelope, ValidationKind::PolicyTooWide);
}

#[tokio::test]
async fn proofs_must_be_delegations() {
    let key = secret_key();
    let subject_pk: [u8; 33] = key.public_key().to_sec1_bytes().as_ref().try_into().unwrap();
    let subject = Did::key(subject_pk);
    let root = NucTokenBuilder::invocation(json!({"bar": 1337}).as_object().cloned().unwrap())
        .subject(subject.clone())
        .command(["nil"])
        .issued_by_root();
    let last = NucTokenBuilder::delegation([policy::op::eq(".foo", json!(42))])
        .subject(subject)
        .audience(Did::key([0xaa; 33]))
        .command(["nil"])
        .issued_by(key);

    let envelope = Chainer::default().chain([root, last]).await;
    Asserter::default().assert_failure(envelope, ValidationKind::ProofsMustBeDelegations);
}

#[tokio::test]
async fn root_key_signature_missing() {
    let key = secret_key();
    let base = delegation(&key).command(["nil"]);
    let root = base.clone().issued_by(key.clone());
    let last = base.issued_by(key);

    let envelope = Chainer::default().chain([root, last]).await;
    Asserter::default().assert_failure(envelope, ValidationKind::RootKeySignatureMissing);
}

#[tokio::test]
async fn subject_not_in_chain() {
    let subject_key = secret_key();
    let key = secret_key();
    let base = delegation(&subject_key).command(["nil"]);
    let root = base.clone().issued_by_root();
    let last = base.issued_by(key);

    let envelope = Chainer::default().chain([root, last]).await;
    Asserter::default().assert_failure(envelope, ValidationKind::SubjectNotInChain);
}

#[tokio::test]
async fn root_token_expired() {
    let now = DateTime::from_timestamp(10, 0).unwrap();
    let expires_at = DateTime::from_timestamp(5, 0).unwrap();

    let key = secret_key();
    let base = delegation(&key).command(["nil"]);
    let root = base.clone().expires_at(expires_at).issued_by_root();
    let last = base.issued_by(key);
    let envelope = Chainer::default().chain([root, last]).await;
    Asserter::default().with_current_time(now).assert_failure(envelope, ValidationKind::TokenExpired);
}

#[tokio::test]
async fn last_token_expired() {
    let now = DateTime::from_timestamp(10, 0).unwrap();
    let expires_at = DateTime::from_timestamp(5, 0).unwrap();

    let key = secret_key();
    let base = delegation(&key).command(["nil"]);
    let root = base.clone().issued_by_root();
    let last = base.expires_at(expires_at).issued_by(key);
    let envelope = Chainer::default().chain([root, last]).await;
    Asserter::default().with_current_time(now).assert_failure(envelope, ValidationKind::TokenExpired);
}

#[tokio::test]
async fn valid_token() {
    let subject_key = SecretKey::random(&mut rand::thread_rng());
    let subject_pk: [u8; 33] = subject_key.public_key().to_sec1_bytes().as_ref().try_into().unwrap();
    let subject = Did::key(subject_pk);
    let rpc_did = Did::key([0xaa; 33]);
    let root =
        NucTokenBuilder::delegation([policy::op::eq(".args.foo", json!(42)), policy::op::eq("$.req.bar", json!(1337))])
            .subject(subject.clone())
            .command(["nil"])
            .issued_by_root();
    let intermediate = NucTokenBuilder::delegation([policy::op::eq(".args.bar", json!(1337))])
        .subject(subject.clone())
        .command(["nil", "bar"])
        .issued_by(subject_key);
    let invocation_key = secret_key();
    let invocation = NucTokenBuilder::invocation(json!({"foo": 42, "bar": 1337}).as_object().cloned().unwrap())
        .subject(subject.clone())
        .audience(rpc_did.clone())
        .command(["nil", "bar", "foo"])
        .issued_by(invocation_key.clone());

    let envelope = Chainer::default().chain([root, intermediate, invocation]).await;
    let parameters =
        ValidationParameters { token_requirements: TokenTypeRequirements::Invocation(rpc_did), ..Default::default() };
    let context = HashMap::from([("req", json!({"bar": 1337}))]);
    let ValidatedNucToken { token, proofs } = Asserter::new(parameters).with_context(context).assert_success(envelope);
    let invocation_issuer_pk: [u8; 33] = invocation_key.public_key().to_sec1_bytes().as_ref().try_into().unwrap();
    assert_eq!(token.issuer, Did::key(invocation_issuer_pk));

    // Ensure the order is right
    assert_eq!(proofs[0].issuer, subject);
    let root_issuer_pk: [u8; 33] = ROOT_SECRET_KEYS[0].public_key().to_sec1_bytes().as_ref().try_into().unwrap();
    assert_eq!(proofs[1].issuer, Did::key(root_issuer_pk));
}

#[tokio::test]
async fn valid_revocation_token() {
    let subject_key = SecretKey::random(&mut rand::thread_rng());
    let subject_pk: [u8; 33] = subject_key.public_key().to_sec1_bytes().as_ref().try_into().unwrap();
    let subject = Did::key(subject_pk);
    let rpc_did = Did::key([0xaa; 33]);
    let root = NucTokenBuilder::delegation([policy::op::eq(".args.foo", json!(42))])
        .subject(subject.clone())
        .command(["nil"])
        .issued_by_root();
    let invocation = NucTokenBuilder::invocation(json!({"foo": 42, "bar": 1337}).as_object().cloned().unwrap())
        .subject(subject.clone())
        .audience(rpc_did.clone())
        .command(["nuc", "revoke"])
        .issued_by(subject_key);

    let envelope = Chainer::default().chain([root, invocation]).await;
    let parameters =
        ValidationParameters { token_requirements: TokenTypeRequirements::Invocation(rpc_did), ..Default::default() };
    Asserter::new(parameters).assert_success(envelope);
}

#[tokio::test]
async fn valid_no_root_keys_needed() {
    let subject_key = SecretKey::random(&mut rand::thread_rng());
    let subject_pk: [u8; 33] = subject_key.public_key().to_sec1_bytes().as_ref().try_into().unwrap();
    let subject = Did::key(subject_pk);
    let token = NucTokenBuilder::delegation([])
        .subject(subject.clone())
        .audience(subject)
        .command(["nil"])
        .issued_by(subject_key);

    let envelope = Chainer::default().chain([token]).await;
    let asserter = Asserter { root_keys: Vec::new(), ..Default::default() };
    asserter.assert_success(envelope);
}

#[tokio::test]
async fn valid_root_token() {
    let key = secret_key();
    let root = delegation(&key).command(["nil"]).issued_by_root();

    let envelope = Chainer::default().chain([root]).await;
    Asserter::default().assert_success(envelope);
}
