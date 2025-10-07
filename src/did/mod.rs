mod error;
mod ethr;
mod key;
mod nil;

pub use error::ParseDidError;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error};
use std::{fmt, str::FromStr};

/// A Decentralised Identifier (Did).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Did {
    /// The legacy `nil` method.
    #[deprecated(
        since = "1.0.0",
        note = "The `did:nil` method is legacy and will be removed the next major version. Use `did:key` instead."
    )]
    Nil { public_key: [u8; 33] },
    /// The `key` method.
    Key { public_key: [u8; 33] },
    /// The `ethr` method.
    Ethr { address: [u8; 20] },
}

impl Did {
    /// Constructs a Did for the `nil` method.
    #[deprecated(
        since = "1.0.0",
        note = "The `did:nil` method is legacy and will be removed the next major version. Use `did:key` instead."
    )]
    #[allow(deprecated)]
    pub fn nil(public_key: [u8; 33]) -> Self {
        Self::Nil { public_key }
    }

    /// Constructs a Did for the `key` method.
    pub fn key(public_key: [u8; 33]) -> Self {
        Self::Key { public_key }
    }

    /// Constructs a Did for the `ethr` method.
    pub fn ethr(address: [u8; 20]) -> Self {
        Self::Ethr { address }
    }
}

impl fmt::Display for Did {
    #[allow(deprecated)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Did::Nil { public_key } => nil::format(public_key),
            Did::Key { public_key } => key::format(public_key),
            Did::Ethr { address } => ethr::format(address),
        };
        write!(f, "{}", s)
    }
}

impl FromStr for Did {
    type Err = ParseDidError;

    #[allow(deprecated)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(s) = s.strip_prefix("did:nil:") {
            let public_key = nil::parse(s)?;
            Ok(Self::Nil { public_key })
        } else if let Some(s) = s.strip_prefix("did:key:") {
            let public_key = key::parse(s)?;
            Ok(Self::Key { public_key })
        } else if let Some(s) = s.strip_prefix("did:ethr:0x") {
            let address = ethr::parse(s)?;
            Ok(Self::Ethr { address })
        } else {
            Err(ParseDidError::NoDid)
        }
    }
}

impl Serialize for Did {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Did {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse::<Did>().map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use rstest::rstest;

    #[rstest]
    #[allow(deprecated)]
    #[case::nil(
        "did:nil:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        Did::nil([0xaa; 33])
    )]
    #[case::key(
        "did:key:zQ3shPE7AAuxa47pSKSz68iK64dEy6mx1g27Gwjaw294Q1XcY",
        Did::key(*b"\x02\x1a\xfa\xca\xde\x02\xde\xca\xff\xba\xbe\x10\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15")
    )]
    #[case::ethr(
        "did:ethr:0xF3beAC30C498D9E26865F34fCAa57dBB935b0D74",
        Did::ethr(hex!("f3beac30c498d9e26865f34fcaa57dbb935b0d74"))
    )]
    fn did_parsing_and_display(#[case] did_string: &str, #[case] expected_did: Did) {
        let parsed: Did = did_string.parse().expect("parse failed");
        assert_eq!(parsed, expected_did);

        let displayed = parsed.to_string();
        assert_eq!(displayed, did_string);
    }

    #[rstest]
    #[case::no_did("foo:bar:aa")]
    #[case::nil_no_method("did:bar")]
    #[case::nil_trailing_colon("did:bar:aa:")]
    #[case::nil_invalid_public_key("did:bar:lol")]
    #[case::key_invalid_multibase("did:key:aaaaaaaaaaaaaaaaa")]
    #[case::key_unsupported_multibase("did:key:baaaaaaaaaaaaaaaaa")]
    #[case::ethr_invalid_address("did:ethr:0xlol")]
    fn parse_invalid_did(#[case] input: &str) {
        Did::from_str(input).expect_err("parse succeeded");
    }
}
