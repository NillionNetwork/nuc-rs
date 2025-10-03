use super::error::ParseDidError;
use multibase::{Base, encode};

const SECP256K1_PREFIX: [u8; 2] = [0xe7, 0x01];

pub(super) fn format(public_key: &[u8; 33]) -> String {
    let mut prefixed_key = Vec::with_capacity(SECP256K1_PREFIX.len() + public_key.len());
    prefixed_key.extend_from_slice(&SECP256K1_PREFIX);
    prefixed_key.extend_from_slice(public_key);
    let multibase_key = encode(Base::Base58Btc, prefixed_key);
    format!("did:key:{multibase_key}")
}

pub(super) fn parse(s: &str) -> Result<[u8; 33], ParseDidError> {
    let (base, input) = multibase::decode(s).map_err(|_| ParseDidError::Multibase)?;
    if base != Base::Base58Btc {
        return Err(ParseDidError::UnsupportedMultibase);
    }
    if !input.starts_with(&SECP256K1_PREFIX) {
        return Err(ParseDidError::UnsupportedMulticodec);
    }
    let public_key: [u8; 33] =
        input[SECP256K1_PREFIX.len()..].try_into().map_err(|_| ParseDidError::InvalidKeyLength)?;
    Ok(public_key)
}
