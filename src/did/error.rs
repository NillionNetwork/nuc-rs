use hex::FromHexError;

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
