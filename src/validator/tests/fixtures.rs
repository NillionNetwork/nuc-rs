use crate::{
    builder::{DelegationBuilder, InvocationBuilder},
    did::Did,
    envelope::NucTokenEnvelope,
    keypair::Keypair,
    signer::{DidMethod, Secp256k1Signer},
    validator::{
        error::{ValidationError, ValidationKind}, NucValidator, TimeProvider, ValidatedNucToken,
        ValidationParameters,
    },
};
use chrono::{DateTime, Utc};
use k256::PublicKey;
use serde::Serialize;
use serde_with::{serde_as, DisplayFromStr};
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
