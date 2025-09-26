use crate::{
    builder::{DelegationBuilder, InvocationBuilder},
    did::Did,
    envelope::NucTokenEnvelope,
    keypair::Keypair,
    signer::{DidMethod, Secp256k1Signer},
    validator::{
        NucValidator, TimeProvider, ValidatedNucToken, ValidationParameters,
        error::{ValidationError, ValidationKind},
    },
};
use chrono::{DateTime, Utc};
use k256::PublicKey;
use serde::Serialize;
use serde_with::{DisplayFromStr, serde_as};
use std::{collections::HashMap, env, sync::LazyLock};

pub(crate) static ROOT_KEYPAIR: LazyLock<Keypair> = LazyLock::new(Keypair::generate);

pub(crate) static ROOT_PUBLIC_KEYS: LazyLock<Vec<PublicKey>> = LazyLock::new(|| {
    let key = ROOT_KEYPAIR.public_key();
    vec![PublicKey::from_sec1_bytes(&key).expect("valid public key")]
});

pub(crate) enum TimeConfig {
    System,
    Mock(DateTime<Utc>),
}

pub(crate) struct MockTimeProvider(pub DateTime<Utc>);

impl TimeProvider for MockTimeProvider {
    fn current_time(&self) -> DateTime<Utc> {
        self.0
    }
}

pub(crate) struct Asserter {
    pub parameters: ValidationParameters,
    pub root_keys: Vec<PublicKey>,
    pub context: HashMap<&'static str, serde_json::Value>,
    pub time_config: TimeConfig,
    pub log_assertions: bool,
}

impl Asserter {
    pub fn new(parameters: ValidationParameters) -> Self {
        Self {
            parameters,
            root_keys: ROOT_PUBLIC_KEYS.clone(),
            context: Default::default(),
            time_config: TimeConfig::System,
            log_assertions: env::var("NUC_VALIDATOR_LOG_ASSERTIONS") == Ok("1".to_string()),
        }
    }

    pub fn with_context(mut self, context: HashMap<&'static str, serde_json::Value>) -> Self {
        self.context = context;
        self
    }

    pub fn with_current_time(mut self, time: DateTime<Utc>) -> Self {
        self.time_config = TimeConfig::Mock(time);
        self
    }

    pub fn into_assertion(self, envelope: &NucTokenEnvelope, expectation: AssertionExpectation) -> Assertion {
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

    pub fn assert_failure<E: Into<ValidationError>>(self, envelope: NucTokenEnvelope, expected_failure: E) {
        let log = self.log_assertions;
        let ValidationError::Validation(kind) = expected_failure.into() else {
            panic!("unexpected error type");
        };
        let assertion = self.into_assertion(&envelope, AssertionExpectation::Failure { kind });
        assertion.validate(log).expect_err("no error");
    }

    pub fn assert_success(self, envelope: NucTokenEnvelope) -> ValidatedNucToken {
        let log = self.log_assertions;
        let assertion = self.into_assertion(&envelope, AssertionExpectation::Success);
        assertion.validate(log).expect("validation failed")
    }
}

impl Default for Asserter {
    fn default() -> Self {
        let parameters = ValidationParameters::default();
        Self::new(parameters)
    }
}

#[derive(Serialize)]
pub(crate) struct Assertion {
    pub input: AssertionInput,
    pub expectation: AssertionExpectation,
}

impl Assertion {
    pub fn log_tokens(envelope: &NucTokenEnvelope) {
        // Log this so we can debug tests based on their output
        println!("Token being asserted: {}", serde_json::to_string_pretty(envelope.token().token()).unwrap());
        println!(
            "Proofs for it: {}",
            serde_json::to_string_pretty(&envelope.proofs().iter().map(|d| &d.token).collect::<Vec<_>>()).unwrap()
        );
    }

    pub fn validate(self, log: bool) -> Result<ValidatedNucToken, ValidationError> {
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
pub(crate) struct AssertionInput {
    pub token: String,
    pub root_keys: Vec<String>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub current_time: DateTime<Utc>,
    pub context: HashMap<&'static str, serde_json::Value>,
    pub parameters: ValidationParameters,
}

#[serde_as]
#[derive(Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub(crate) enum AssertionExpectation {
    Success,
    Failure {
        #[serde_as(as = "DisplayFromStr")]
        kind: ValidationKind,
    },
}

pub(crate) fn keypair() -> Keypair {
    Keypair::generate()
}

pub(crate) fn root_signer() -> Secp256k1Signer {
    ROOT_KEYPAIR.signer(DidMethod::Key)
}

// Create a delegation with the most common fields already set so we don't need to deal
// with them in every single test.
pub(crate) fn delegation(subject: &Keypair) -> DelegationBuilder {
    DelegationBuilder::new().audience(Did::key([0xde; 33])).subject(subject.to_did(DidMethod::Key))
}

// Same as the above but for invocations
#[allow(dead_code)]
pub(crate) fn invocation(subject: &Keypair) -> InvocationBuilder {
    InvocationBuilder::new().audience(Did::key([0xde; 33])).subject(subject.to_did(DidMethod::Key))
}

use crate::envelope::SignaturesValidated;

/// Builds a standard two-link delegation chain (`root -> second`).
pub(crate) async fn build_two_link_delegation_chain<F, G>(
    root_modifier: F,
    second_modifier: G,
) -> NucTokenEnvelope<SignaturesValidated>
where
    F: FnOnce(DelegationBuilder) -> DelegationBuilder,
    G: FnOnce(DelegationBuilder) -> DelegationBuilder,
{
    let key = keypair();
    let root_signer = root_signer();
    let key_signer = key.signer(DidMethod::Key);

    // Build the root delegation with sensible defaults
    let root_builder = DelegationBuilder::new()
        .command(["nil"])
        .audience(key.to_did(DidMethod::Key))
        .subject(key.to_did(DidMethod::Key));

    // Apply test-specific modifications to the root
    let root_builder = root_modifier(root_builder);

    let root = root_builder.sign(&root_signer).await.expect("failed to build root delegation");

    // Build the second delegation extending the root
    let second_builder = DelegationBuilder::extending(root)
        .expect("failed to extend from root")
        .command(["nil"]) // Inherits command by default, can be overridden
        .audience(Did::key([0xde; 33])); // Default final audience

    // Apply test-specific modifications to the second token
    let second_builder = second_modifier(second_builder);

    second_builder.sign(&key_signer).await.expect("failed to build second delegation")
}

/// Builds a standard two-token chain (`root delegation -> invocation`).
pub(crate) async fn build_invocation_with_one_proof<F, G>(
    delegation_modifier: F,
    invocation_modifier: G,
) -> NucTokenEnvelope<SignaturesValidated>
where
    F: FnOnce(DelegationBuilder) -> DelegationBuilder,
    G: FnOnce(InvocationBuilder) -> InvocationBuilder,
{
    let subject_key = keypair();
    let root_signer = root_signer();
    let subject_signer = subject_key.signer(DidMethod::Key);
    let subject_did = subject_key.to_did(DidMethod::Key);

    // Build the root delegation with sensible defaults
    let root_builder = DelegationBuilder::new().command(["nil"]).audience(subject_did.clone()).subject(subject_did);

    // Apply test-specific modifications to the delegation
    let root_builder = delegation_modifier(root_builder);

    let root_delegation = root_builder.sign(&root_signer).await.expect("failed to build root delegation");

    // Build the invocation extending the delegation
    let invocation_builder = InvocationBuilder::extending(root_delegation)
        .command(["nil"]) // Inherits command by default, can be overridden
        .audience(Did::key([0xaa; 33])); // Default final audience

    // Apply test-specific modifications to the invocation
    let invocation_builder = invocation_modifier(invocation_builder);

    invocation_builder.sign(&subject_signer).await.expect("failed to build invocation")
}
