use crate::did::Did;
use crate::policy::Policy;
use chrono::{DateTime, Utc};
use hex::FromHexError;
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use std::{fmt, str::FromStr};

/// A JSON object.
pub type JsonObject = serde_json::Map<String, serde_json::Value>;

/// A Nillion Nuc token.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NucToken {
    /// The issuer of the token (iss).
    ///
    /// This is the principal that created and signed the token. In a delegation chain,
    /// the issuer of a token must be the subject of the proof it is extending.
    #[serde(rename = "iss")]
    pub issuer: Did,

    /// The audience of the token (aud).
    ///
    /// This is the principal that the token is intended for, which will be expected
    /// to verify and honor it. This is typically the DID of a resource server.
    #[serde(rename = "aud")]
    pub audience: Did,

    /// The subject of the token (sub).
    ///
    /// This is the principal that is being granted the authority of this token.
    /// In a delegation, this is the identity that can use this token as a proof
    /// to issue further, more attenuated tokens.
    #[serde(rename = "sub")]
    pub subject: Did,

    /// The first timestamp at which this token is valid.
    #[serde(
        rename = "nbf",
        default,
        with = "chrono::serde::ts_seconds_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub not_before: Option<DateTime<Utc>>,

    /// The timestamp at which this token becomes invalid.
    #[serde(
        rename = "exp",
        default,
        with = "chrono::serde::ts_seconds_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub expires_at: Option<DateTime<Utc>>,

    /// The command that is being invoked or the authority is being delegated for.
    #[serde(rename = "cmd")]
    pub command: Command,

    /// The token body.
    #[serde(flatten)]
    pub body: TokenBody,

    /// Metadata associated to this token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<JsonObject>,

    /// The token nonce.
    #[serde(with = "hex::serde")]
    pub nonce: Vec<u8>,

    /// The hash of the proofs in this token.
    #[serde(rename = "prf", default)]
    pub proofs: Vec<ProofHash>,
}

/// The hash of a proof.
#[derive(Clone, Copy, Debug, Eq, Hash, SerializeDisplay, DeserializeFromStr, PartialEq)]
pub struct ProofHash(pub [u8; 32]);

impl fmt::Display for ProofHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hash = hex::encode(self.0);
        write!(f, "{hash}")
    }
}

impl FromStr for ProofHash {
    type Err = FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut data = [0; 32];
        hex::decode_to_slice(s, &mut data)?;
        Ok(Self(data))
    }
}

/// A command.
#[derive(Clone, Debug, SerializeDisplay, DeserializeFromStr, PartialEq)]
pub struct Command(pub Vec<String>);

impl Command {
    /// Check if this command is an attenuation of another one.
    pub fn is_attenuation_of(&self, other: &Command) -> bool {
        if self.0.len() < other.0.len() {
            // We can't be an attenuation if we're shorter.
            false
        } else {
            // Take the first `other.len()` segments from ourselves.
            let prefix = self.0.iter().take(other.0.len());

            // Ensure the other one starts with those segments.
            other.0.iter().eq(prefix)
        }
    }
}

impl From<Vec<String>> for Command {
    fn from(command: Vec<String>) -> Self {
        Self(command)
    }
}

impl From<&[&str]> for Command {
    fn from(command: &[&str]) -> Self {
        let command = command.iter().map(ToString::to_string).collect();
        Self(command)
    }
}

impl<const N: usize> From<[&str; N]> for Command {
    fn from(command: [&str; N]) -> Self {
        Self::from(command.as_slice())
    }
}

impl FromStr for Command {
    type Err = MalformedCommandError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with('/') {
            return Err(MalformedCommandError::LeadingSlash);
        }
        let s = &s[1..];
        if s.is_empty() {
            return Ok(Self(vec![]));
        }
        let mut segments = Vec::new();
        for segment in s.split("/") {
            if segment.is_empty() {
                return Err(MalformedCommandError::EmptySegment);
            }
            segments.push(segment.into());
        }
        Ok(Self(segments))
    }
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return write!(f, "/");
        }
        for segment in &self.0 {
            write!(f, "/{segment}")?;
        }
        Ok(())
    }
}

/// The body of a token
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub enum TokenBody {
    #[serde(rename = "pol")]
    Delegation(Vec<Policy>),

    #[serde(rename = "args")]
    Invocation(JsonObject),
}

/// An encountered error when parsing a command.
#[derive(Debug, thiserror::Error)]
pub enum MalformedCommandError {
    #[error("no leading slash")]
    LeadingSlash,

    #[error("empty segment")]
    EmptySegment,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy;
    use rstest::rstest;
    use serde_json::json;

    #[rstest]
    #[case::root("/", &[])]
    #[case::one("/nil", &["nil"])]
    #[case::two("/nil/bar", &["nil", "bar"])]
    fn parse_valid_commands(#[case] input: &str, #[case] expected: &[&str]) {
        let parsed: Command = input.parse().expect("parsing failed");
        assert_eq!(&parsed.0, expected);
        assert_eq!(parsed.to_string(), input);
    }

    #[rstest]
    #[case::empty("")]
    #[case::leading_double_slash("//")]
    #[case::trailing_slash("/nil/")]
    #[case::double_slash_in_middle("/nil//a")]
    fn parse_invalid_commands(#[case] input: &str) {
        input.parse::<Command>().expect_err("parsing succeeded");
    }

    #[test]
    fn parse_valid_proof_hash() {
        let input = "f4f04af6a832bcd8a6855df5d0242c9a71e9da17faeb2d33b30c8903f1b5a944";
        let hash: ProofHash = input.parse().expect("parse failed");
        assert_eq!(
            &hash.0,
            b"\xf4\xf0J\xf6\xa82\xbc\xd8\xa6\x85]\xf5\xd0$,\x9aq\xe9\xda\x17\xfa\xeb-3\xb3\x0c\x89\x03\xf1\xb5\xa9D"
        );
        assert_eq!(hash.to_string(), input);
    }

    #[test]
    fn parse_did_key_token() {
        let input = r#"
{
  "iss": "did:key:zQ3shPE7AAuxa47pSKSz68iK64dEy6mx1g27Gwjaw294Q1XcY",
  "aud": "did:key:zQ3shokFTS3dS2tPR6hL8WdG2a2h2nkr4zv4x1v6b34tMAu1Y",
  "sub": "did:key:zQ3shPE7AAuxa47pSKSz68iK64dEy6mx1g27Gwjaw294Q1XcY",
  "cmd": "/nil/db/read",
  "pol": [],
  "nonce": "beef"
}"#;
        let token: NucToken = serde_json::from_str(input).expect("parsing failed");
        // Check that the issuer is the expected did:key
        let expected_issuer = Did::key(*b"\x02\x1a\xfa\xca\xde\x02\xde\xca\xff\xba\xbe\x10\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15");
        assert_eq!(token.issuer, expected_issuer);
    }

    #[allow(deprecated)]
    mod legacy {
        use super::*;
        use crate::did::Did;
        use chrono::DateTime;

        #[test]
        fn parse_minimal_delegation() {
            let input = r#"
{
  "iss": "did:nil:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "aud": "did:nil:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "sub": "did:nil:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "cmd": "/nil/db/read",
  "pol": [
    ["==", ".foo", 42]
  ],
  "nonce": "beef"
}"#;
            serde_json::from_str::<NucToken>(input).expect("parsing failed");
        }

        #[test]
        fn parse_full_delegation() {
            let input = r#"
{
  "iss": "did:nil:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "aud": "did:nil:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "sub": "did:nil:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "cmd": "/nil/db/read",
  "nbf": 1740494955,
  "exp": 1740495955,
  "pol": [
    ["==", ".foo", 42]
  ],
  "meta": {
    "name": "bob"
  },
  "nonce": "beef",
  "prf": ["f4f04af6a832bcd8a6855df5d0242c9a71e9da17faeb2d33b30c8903f1b5a944"]
}"#;
            let token: NucToken = serde_json::from_str(input).expect("parsing failed");
            #[allow(deprecated)]
            let expected = NucToken {
                issuer: Did::nil([0xaa; 33]),
                audience: Did::nil([0xbb; 33]),
                subject: Did::nil([0xcc; 33]),
                not_before: Some(DateTime::from_timestamp(1740494955, 0).unwrap()),
                expires_at: Some(DateTime::from_timestamp(1740495955, 0).unwrap()),
                command: ["nil", "db", "read"].into(),
                body: TokenBody::Delegation(vec![policy::op::eq(".foo", json!(42))]),
                proofs: vec![ProofHash(*b"\xf4\xf0J\xf6\xa82\xbc\xd8\xa6\x85]\xf5\xd0$,\x9aq\xe9\xda\x17\xfa\xeb-3\xb3\x0c\x89\x03\xf1\xb5\xa9D")],
                nonce: b"\xbe\xef".to_vec(),
                meta: Some(json!({ "name": "bob" }).as_object().cloned().unwrap()),
            };
            assert_eq!(token, expected);

            // Ensure `token -> string -> token` gives us back the original token
            let serialized = serde_json::to_string(&token).expect("serialize failed");
            let deserialized: NucToken = serde_json::from_str(&serialized).expect("deserialize failed");
            assert_eq!(deserialized, token);
        }

        #[test]
        fn parse_minimal_invocation() {
            let input = r#"
{
  "iss": "did:nil:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "aud": "did:nil:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "sub": "did:nil:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "cmd": "/nil/db/read",
  "args": {
    "bar": 42
  },
  "nonce": "beef"
}"#;
            serde_json::from_str::<NucToken>(input).expect("parsing failed");
        }

        #[test]
        fn parse_full_invocation() {
            let input = r#"
{
  "iss": "did:nil:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "aud": "did:nil:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "sub": "did:nil:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "cmd": "/nil/db/read",
  "nbf": 1740494955,
  "exp": 1740495955,
  "args": {
    "foo": 42
  },
  "meta": {
    "name": "bob"
  },
  "nonce": "beef",
  "prf": ["f4f04af6a832bcd8a6855df5d0242c9a71e9da17faeb2d33b30c8903f1b5a944"]
}"#;
            let token: NucToken = serde_json::from_str(input).expect("parsing failed");
            #[allow(deprecated)]
            let expected = NucToken {
                issuer: Did::nil([0xaa; 33]),
                audience: Did::nil([0xbb; 33]),
                subject: Did::nil([0xcc; 33]),
                not_before: Some(DateTime::from_timestamp(1740494955, 0).unwrap()),
                expires_at: Some(DateTime::from_timestamp(1740495955, 0).unwrap()),
                command: ["nil", "db", "read"].into(),
                body: TokenBody::Invocation(json!({ "foo": 42 }).as_object().cloned().unwrap()),
                proofs: vec![ProofHash(*b"\xf4\xf0J\xf6\xa82\xbc\xd8\xa6\x85]\xf5\xd0$,\x9aq\xe9\xda\x17\xfa\xeb-3\xb3\x0c\x89\x03\xf1\xb5\xa9D")],
                nonce: b"\xbe\xef".to_vec(),
                meta: Some(json!({ "name": "bob" }).as_object().cloned().unwrap()),
            };
            assert_eq!(token, expected);

            // Ensure `token -> string -> token` gives us back the original token
            let serialized = serde_json::to_string(&token).expect("serialize failed");
            let deserialized: NucToken = serde_json::from_str(&serialized).expect("deserialize failed");
            assert_eq!(deserialized, token);
        }

        #[test]
        fn parse_mixed_delegation_invocation() {
            // This has both `args` and `poll`.
            let input = r#"
{
  "iss": "did:nil:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "aud": "did:nil:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "sub": "did:nil:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "cmd": "/nil/db/read",
  "args": {
    "bar": 42
  },
  "pol": [
    ["==", ".foo", 42]
  ],
  "nonce": "beef"
}"#;
            serde_json::from_str::<NucToken>(input).expect_err("parsing succeeded");
        }
    }

    #[rstest]
    #[case::empty_same(&[], &[], true)]
    #[case::empty_different(&["nil"], &[], true)]
    #[case::same(&["nil"], &["nil"], true)]
    #[case::prefix_match(&["nil", "bar"], &["nil"], true)]
    #[case::longer(&["nil"], &["nil", "bar"], false)]
    #[case::different_prefix(&["nil", "foo"], &["nil", "bar"], false)]
    #[case::different_longer_prefix(&["nil", "bar", "a"], &["nil", "bar", "b"], false)]
    #[case::different(&["nil"], &["bar"], false)]
    fn command_is_attenuation(#[case] left: &[&str], #[case] right: &[&str], #[case] expected: bool) {
        let left = Command::from(left);
        let right = Command::from(right);
        assert_eq!(left.is_attenuation_of(&right), expected);
    }
}

pub mod eip712 {
    use crate::token::{NucToken, TokenBody};
    use ethers::types::transaction::eip712::Eip712DomainType;
    use ethers::types::transaction::eip712::Types;
    use serde::Serialize;
    use serde_json::Value;

    #[derive(Clone, Debug, Serialize)]
    pub struct Eip712DelegationPayload {
        pub iss: String,
        pub aud: String,
        pub sub: String,
        pub cmd: String,
        #[serde(serialize_with = "to_string")]
        pub pol: Value,
        pub nbf: u64,
        pub exp: u64,
        pub nonce: String,
        pub prf: Vec<String>,
    }

    #[derive(Clone, Debug, Serialize)]
    pub struct Eip712InvocationPayload {
        pub iss: String,
        pub aud: String,
        pub sub: String,
        pub cmd: String,
        #[serde(serialize_with = "to_string")]
        pub args: Value,
        pub nbf: u64,
        pub exp: u64,
        pub nonce: String,
        pub prf: Vec<String>,
    }

    impl From<NucToken> for Eip712DelegationPayload {
        fn from(token: NucToken) -> Self {
            let pol = match token.body {
                TokenBody::Delegation(policies) => serde_json::to_value(policies).unwrap(),
                TokenBody::Invocation(_) => panic!("Cannot create delegation payload from invocation token"),
            };

            Self {
                iss: token.issuer.to_string(),
                aud: token.audience.to_string(),
                sub: token.subject.to_string(),
                cmd: token.command.to_string(),
                pol,
                nbf: token.not_before.map(|dt| dt.timestamp() as u64).unwrap_or(0),
                exp: token.expires_at.map(|dt| dt.timestamp() as u64).unwrap_or(0),
                nonce: hex::encode(token.nonce),
                prf: token.proofs.into_iter().map(|p| p.to_string()).collect(),
            }
        }
    }

    impl From<NucToken> for Eip712InvocationPayload {
        fn from(token: NucToken) -> Self {
            let args = match token.body {
                TokenBody::Invocation(args) => serde_json::to_value(args).unwrap(),
                TokenBody::Delegation(_) => panic!("Cannot create invocation payload from delegation token"),
            };

            Self {
                iss: token.issuer.to_string(),
                aud: token.audience.to_string(),
                sub: token.subject.to_string(),
                cmd: token.command.to_string(),
                args,
                nbf: token.not_before.map(|dt| dt.timestamp() as u64).unwrap_or(0),
                exp: token.expires_at.map(|dt| dt.timestamp() as u64).unwrap_or(0),
                nonce: hex::encode(token.nonce),
                prf: token.proofs.into_iter().map(|p| p.to_string()).collect(),
            }
        }
    }

    pub fn get_eip712_delegation_types() -> Types {
        let mut types = Types::new();
        types.insert(
            "NucDelegationPayload".to_string(),
            vec![
                Eip712DomainType { name: "iss".into(), r#type: "string".into() },
                Eip712DomainType { name: "aud".into(), r#type: "string".into() },
                Eip712DomainType { name: "sub".into(), r#type: "string".into() },
                Eip712DomainType { name: "cmd".into(), r#type: "string".into() },
                Eip712DomainType { name: "pol".into(), r#type: "string".into() },
                Eip712DomainType { name: "nbf".into(), r#type: "uint256".into() },
                Eip712DomainType { name: "exp".into(), r#type: "uint256".into() },
                Eip712DomainType { name: "nonce".into(), r#type: "string".into() },
                Eip712DomainType { name: "prf".into(), r#type: "string[]".into() },
            ],
        );
        types
    }

    pub fn get_eip712_invocation_types() -> Types {
        let mut types = Types::new();
        types.insert(
            "NucInvocationPayload".to_string(),
            vec![
                Eip712DomainType { name: "iss".into(), r#type: "string".into() },
                Eip712DomainType { name: "aud".into(), r#type: "string".into() },
                Eip712DomainType { name: "sub".into(), r#type: "string".into() },
                Eip712DomainType { name: "cmd".into(), r#type: "string".into() },
                Eip712DomainType { name: "args".into(), r#type: "string".into() },
                Eip712DomainType { name: "nbf".into(), r#type: "uint256".into() },
                Eip712DomainType { name: "exp".into(), r#type: "uint256".into() },
                Eip712DomainType { name: "nonce".into(), r#type: "string".into() },
                Eip712DomainType { name: "prf".into(), r#type: "string[]".into() },
            ],
        );
        types
    }

    fn to_string<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: Serialize,
        S: serde::Serializer,
    {
        let s = serde_json::to_string(value).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&s)
    }
}
