use hex::FromHexError;

/// An error when parsing a Did.
#[derive(Debug, thiserror::Error)]
pub enum ParseDidError {
    /// The string is missing the "did:" prefix.
    #[error("not a valid Did prefix")]
    NoDid,

    /// The public key contains invalid hexadecimal characters.
    #[error("invalid public key hex characters: {0}")]
    PublicKeyChars(#[from] FromHexError),

    /// The address contains invalid hexadecimal characters.
    #[error("invalid address hex characters: {0}")]
    AddressChars(#[source] FromHexError),

    /// The `did:key` value has an invalid multibase encoding.
    #[error("invalid multibase encoding")]
    Multibase,

    /// The `did:key` value uses an unsupported multibase encoding.
    #[error("unsupported multibase encoding, expected base58btc")]
    UnsupportedMultibase,

    /// The `did:key` value uses an unsupported multicodec.
    #[error("unsupported multicodec, expected secp256k1-pub")]
    UnsupportedMulticodec,

    /// The public key has an invalid length.
    #[error("invalid public key length")]
    InvalidKeyLength,
}
