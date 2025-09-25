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
//! *   [`Keypair`]: For generating and managing cryptographic identities.
//! *   [`NucTokenBuilder`]: For constructing delegation and invocation tokens.
//! *   [`NucTokenEnvelope`]: For decoding and handling token chains.
//! *   [`NucValidator`]: For verifying the integrity and permissions of a token chain.
//!
//! For a complete guide, please see the **[Usage Documentation](https://github.com/NillionNetwork/nuc-rs/blob/main/DOCUMENTATION.md)**.
//!
//! ## Quick Example
//!
//! ```rust
//! use nillion_nucs::{
//!     builder::NucTokenBuilder,
//!     did::Did,
//!     keypair::Keypair,
//!     signer::DidMethod,
//! };
//!
//! async fn build_token() {
//!     let keypair = Keypair::generate();
//!     let signer = keypair.signer(DidMethod::Key);
//!     let audience_did = Keypair::generate().to_did(DidMethod::Key);
//!
//!     let token_string = NucTokenBuilder::delegation(vec![])
//!         .audience(audience_did.clone())
//!         .subject(audience_did)
//!         .command(["admin", "god-mode"])
//!         .build(&signer)
//!         .await
//!         .unwrap();
//!
//!     println!("Generated token: {}", token_string);
//! }
//! ```
//!
//! [`NucTokenBuilder`]: builder::NucTokenBuilder
//! [`NucTokenEnvelope`]: envelope::NucTokenEnvelope
//! [`NucValidator`]: validator::NucValidator

pub mod builder;
pub mod did;
pub mod envelope;
pub mod keypair;
pub mod policy;
pub mod selector;
pub mod signer;
pub mod token;
pub mod validator;

pub use k256;
pub use keypair::Keypair;
pub use signer::{DidMethod, Secp256k1Signer, Signer};
