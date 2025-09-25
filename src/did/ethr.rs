use super::error::ParseDidError;
use ethers::types::Address;
use ethers::utils::to_checksum;

pub(super) fn format(address: &[u8; 20]) -> String {
    let addr = Address::from(*address);
    format!("did:ethr:{}", to_checksum(&addr, None))
}

pub(super) fn parse(s: &str) -> Result<[u8; 20], ParseDidError> {
    let mut address = [0; 20];
    hex::decode_to_slice(s, &mut address).map_err(ParseDidError::AddressChars)?;
    Ok(address)
}
