# Usage Documentation

## Installation

The library can be added to your project using Cargo:

```bash
# Recommended:
cargo add nillion-nucs --git https://github.com/NillionNetwork/nuc-rs --rev <LATEST_COMMIT_HASH>

# Or, to use the main branch:
cargo add nillion-nucs --git https://github.com/NillionNetwork/nuc-rs --branch main
```

```rust
use nillion_nucs::{
    builder::DelegationBuilder,
    did::Did,
    envelope::NucTokenEnvelope,
    signer::{DidMethod, Signer},
    validator::NucValidator,
};
```

## Core Concepts

A Nuc is a type of capability-based authorisation token inspired by the UCAN specification. It grants specific permissions from a sender to a receiver. Three core claims define the actors in this relationship:

| Claim     | Role                    | Description                                                                                                                                                   |
|:----------|:------------------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **`iss`** | **Issuer (Sender)**     | The principal who created and signed the token.                                                                                                               |
| **`aud`** | **Audience (Receiver)** | The principal the token is addressed to. This is the only entity that can use (i.e., invoke or delegate) the token.                                           |
| **`sub`** | **Subject**             | The principal the token is "about". It represents the identity whose authority is being granted. This value must stay the same throughout a delegation chain. |

In a simple, two-party delegation, the `aud` and `sub` are often the same. When the Audience creates a new, chained token, it becomes the `iss` of the new token.

## Complete Usage Example

This example demonstrates the primary workflow of creating delegation and invocation tokens:

```rust
use nillion_nucs::{
    builder::{DelegationBuilder, InvocationBuilder},
    did::Did,
    envelope::NucTokenEnvelope,
    policy,
    signer::{DidMethod, NucSigner, Signer},
    validator::{NucValidator, TokenTypeRequirements, ValidationParameters},
};
use serde_json::json;
use std::{collections::HashMap, time::Duration};

async fn example() {
    // Step 1: Create Signers for different parties
    // A root authority (e.g., for a server-side process with a private key)
    let root_signer = Signer::from_private_key(
        &[1; 32], // Use a real private key in production
        DidMethod::Key,
    );

    // A user identity, newly generated for this session
    let user_signer = Signer::generate(DidMethod::Key);

    // A service that will receive the final invocation
    let service_signer = Signer::generate(DidMethod::Key);

    // Step 2: Get the DIDs for the user and service
    let user_did = user_signer.did().clone();
    let service_did = service_signer.did().clone();

    // Step 3: Build a root delegation token
    // This grants capabilities from the root to the user
    let root_delegation_envelope = DelegationBuilder::new()
        .audience(user_did.clone())
        .subject(user_did.clone())
        .command(["nil", "db", "collections", "read"])
        .policies(vec![
            policy::op::eq(".command", json!("/nil/db/collections")),
            policy::op::ne(".args.collection", json!("secrets")),
        ])
        .expires_in(Duration::from_secs(3600)) // Expires in 1 hour
        .sign(&*root_signer)
        .await
        .unwrap();

    // Step 4: Build an invocation token from the delegation
    // The user invokes their granted capability for the service
    let invocation_envelope = InvocationBuilder::extending(root_delegation_envelope)
        .unwrap()
        .audience(service_did.clone())
        .command(["nil", "db", "collections", "read"])
        .arguments(json!({ "collection": "users" }))
        .sign(&*user_signer)
        .await
        .unwrap();

    // Step 5: Serialize for transmission
    let token_string = invocation_envelope.unvalidate().encode();
    println!("Token to send: {}", token_string);

    // Step 6: (Optional) Decode and validate the token
    // This would typically happen on the receiving service
    let decoded_envelope = NucTokenEnvelope::decode(&token_string).unwrap();

    let validator = NucValidator::new(vec![root_signer.public_key()]).unwrap();
    let params = ValidationParameters {
        token_requirements: TokenTypeRequirements::Invocation(service_did),
        ..Default::default()
    };
    let context: HashMap<&str, serde_json::Value> =
        HashMap::from([("environment", json!("production"))]);

    match validator.validate(decoded_envelope, params, &context) {
        Ok(_) => println!("Token is valid!"),
        Err(e) => eprintln!("Validation failed: {}", e),
    }
}
```
