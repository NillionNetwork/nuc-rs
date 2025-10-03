use super::error::ParseDidError;

pub(super) fn format(public_key: &[u8; 33]) -> String {
    format!("did:nil:{}", hex::encode(public_key))
}

pub(super) fn parse(s: &str) -> Result<[u8; 33], ParseDidError> {
    let mut public_key = [0; 33];
    hex::decode_to_slice(s, &mut public_key)?;
    Ok(public_key)
}
