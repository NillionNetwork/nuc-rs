use ethers::types::Address;
use ethers::utils::to_checksum;
use hex::FromHexError;
use multibase::{Base, encode};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error};
use std::{fmt, str::FromStr};

const SECP256K1_PREFIX: [u8; 2] = [0xe7, 0x01];

/// A decentralized Id.
#[derive(Clone, Debug, PartialEq)]
pub enum Did {
    /// The legacy `nil` method.
    #[deprecated(
        since = "0.2.0",
        note = "The `did:nil` method is legacy and will be removed in 0.3.0. Use `did:key` instead."
    )]
    Nil { public_key: [u8; 33] },
    /// The `key` method.
    Key { public_key: [u8; 33] },
    /// The `ethr` method.
    Ethr { address: [u8; 20] },
}

impl Did {
    /// Construct a Did for the `nil` method.
    #[deprecated(
        since = "0.2.0",
        note = "The `did:nil` method is legacy and will be removed in 0.3.0. Use `did:key` instead."
    )]
    #[allow(deprecated)]
    pub fn nil(public_key: [u8; 33]) -> Self {
        Self::Nil { public_key }
    }

    /// Construct a Did for the `key` method.
    pub fn key(public_key: [u8; 33]) -> Self {
        Self::Key { public_key }
    }

    /// Construct a Did for the `ethr` method.
    pub fn ethr(address: [u8; 20]) -> Self {
        Self::Ethr { address }
    }
}

impl fmt::Display for Did {
    #[allow(deprecated)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Did::Nil { public_key } => {
                let public_key = hex::encode(public_key);
                write!(f, "did:nil:{public_key}")
            }
            Did::Key { public_key } => {
                let mut prefixed_key = Vec::with_capacity(SECP256K1_PREFIX.len() + public_key.len());
                prefixed_key.extend_from_slice(&SECP256K1_PREFIX);
                prefixed_key.extend_from_slice(public_key);
                let multibase_key = encode(Base::Base58Btc, prefixed_key);
                write!(f, "did:key:{multibase_key}")
            }
            Did::Ethr { address } => {
                let addr = Address::from(*address);
                write!(f, "did:ethr:{}", to_checksum(&addr, None))
            }
        }
    }
}

impl FromStr for Did {
    type Err = ParseDidError;

    #[allow(deprecated)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(s) = s.strip_prefix("did:nil:") {
            let mut public_key = [0; 33];
            hex::decode_to_slice(s, &mut public_key).map_err(ParseDidError::PublicKeyChars)?;
            Ok(Self::Nil { public_key })
        } else if let Some(s) = s.strip_prefix("did:key:") {
            let (base, input) = multibase::decode(s).map_err(|_| ParseDidError::Multibase)?;
            if base != Base::Base58Btc {
                return Err(ParseDidError::UnsupportedMultibase);
            }
            if !input.starts_with(&SECP256K1_PREFIX) {
                return Err(ParseDidError::UnsupportedMulticodec);
            }
            let public_key: [u8; 33] =
                input[SECP256K1_PREFIX.len()..].try_into().map_err(|_| ParseDidError::InvalidKeyLength)?;
            Ok(Self::Key { public_key })
        } else if let Some(s) = s.strip_prefix("did:ethr:0x") {
            let mut address = [0; 20];
            hex::decode_to_slice(s, &mut address).map_err(ParseDidError::AddressChars)?;
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

/// An error when parsing a DID.
#[derive(Debug, thiserror::Error)]
pub enum ParseDidError {
    #[error("not a valid Did prefix")]
    NoDid,

    #[error("invalid public key hex characters: {0}")]
    PublicKeyChars(#[from] FromHexError),

    #[error("invalid address hex characters: {0}")]
    AddressChars(#[source] FromHexError),

    #[error("invalid multibase encoding")]
    Multibase,

    #[error("unsupported multibase encoding, expected base58btc")]
    UnsupportedMultibase,

    #[error("unsupported multicodec, expected secp256k1-pub")]
    UnsupportedMulticodec,

    #[error("invalid public key length")]
    InvalidKeyLength,
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
        // Test parsing
        let parsed: Did = did_string.parse().expect("parse failed");
        assert_eq!(parsed, expected_did);

        // Test display
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
