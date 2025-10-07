//! A Rust crate for creating and validating Nucs, Nillion's UCAN-based
//! network authentication mechanism.
//!
//! This library provides tools to build, sign, encode, decode, and validate
//! authorization tokens, enabling capability-based security models.
//!
//! # Getting Started
//!
//! The primary entry points for using this crate are:
//!
//! *   [`Signer`]: For generating and managing cryptographic identities.
//! *   [`DelegationBuilder`] and [`InvocationBuilder`]: For constructing delegation and invocation tokens.
//! *   [`NucTokenEnvelope`]: For decoding and handling token chains.
//! *   [`NucValidator`]: For verifying the integrity and permissions of a token chain.
//!
//! For a complete guide, please see the **[Usage Documentation](https://github.com/NillionNetwork/nuc-rs/blob/main/DOCUMENTATION.md)**.
//!
//! ## Quick Example
//!
//! ```rust
//! use nillion_nucs::{
//!     builder::DelegationBuilder,
//!     did::Did,
//!     signer::{DidMethod, Signer},
//! };
//!
//! async fn build_token() {
//!     let signer = Signer::generate(DidMethod::Key);
//!     let audience_signer = Signer::generate(DidMethod::Key);
//!     let audience_did = audience_signer.did().clone();
//!
//!     let token_string = DelegationBuilder::new()
//!         .audience(audience_did.clone())
//!         .subject(audience_did)
//!         .command(["admin", "god-mode"])
//!         .sign_and_serialize(&*signer)
//!         .await
//!         .unwrap();
//!
//!     println!("Generated token: {}", token_string);
//! }
//! ```
//!
//! [`DelegationBuilder`]: builder::DelegationBuilder
//! [`InvocationBuilder`]: builder::InvocationBuilder
//! [`NucTokenEnvelope`]: envelope::NucTokenEnvelope
//! [`NucValidator`]: validator::NucValidator
//! [`Signer`]: signer::Signer
extern crate core;

pub mod builder;
pub mod did;
pub mod envelope;
pub mod policy;
pub mod selector;
pub mod signer;
pub mod token;
pub mod validator;

/// Re-export of the `k256` crate for convenience.
pub use k256;
/// Core components for creating and signing Nuc tokens.
pub use signer::{DidMethod, NucSigner, Secp256k1Signer, Signer};
