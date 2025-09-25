# Usage Documentation

## Installation

Add `nillion-nucs` to your `Cargo.toml`:

```toml
[dependencies]
nillion-nucs = "0.1.0"
```

## Core Concepts

A NUC (Nillion User Controlled) token is a type of capability-based authorisation token inspired by the UCAN specification. It grants specific permissions from a sender to a receiver. Three core claims define the actors in this relationship:

| Claim     | Role                    | Description                                                                                                                                                   |
|:----------|:------------------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **`iss`** | **Issuer (Sender)**     | The principal who created and signed the token.                                                                                                               |
| **`aud`** | **Audience (Receiver)** | The principal the token is addressed to. This is the only entity that can use (i.e., invoke or delegate) the token.                                           |
| **`sub`** | **Subject**             | The principal the token is "about". It represents the identity whose authority is being granted. This value must stay the same throughout a delegation chain. |

In a simple, two-party delegation, the `aud` and
`sub` are often the same. When the Audience creates a new, chained token, it becomes the `iss` of the new token.

## Complete Usage Example

This example demonstrates the primary workflow:

1. A `root` authority delegates a capability to a `user`.
2. The `user` further delegates a more specific capability to a `service`.
3. The `service` creates an invocation to execute the capability.
4. The final token chain is validated.

```rust
use nillion_nucs::{
    builder::NucTokenBuilder,
    did::Did,
    envelope::NucTokenEnvelope,
    keypair::Keypair,
    policy,
    signer::DidMethod,
    validator::{ValidationConfig, NucValidator},
};
use serde_json::json;
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // === Step 1: Create Keypairs for all actors ===
    let root_keypair = Keypair::generate();
    let user_keypair = Keypair::generate();
    let service_keypair = Keypair::generate();

    // Create signers from the keypairs
    let root_signer = root_keypair.signer(DidMethod::Key);
    let user_signer = user_keypair.signer(DidMethod::Key);
    let service_signer = service_keypair.signer(DidMethod::Key);

    // === Step 2: Root delegates to User ===
    // The root authority grants the user the ability to perform any read
    // operation on the "users" collection.
    let root_delegation_str = NucTokenBuilder::delegation(vec![
        policy::op::eq(".command", json!("/db/read")),
        policy::op::eq(".args.collection", json!("users")),
    ])
        .audience(user_keypair.to_did(DidMethod::Key))
        .subject(user_keypair.to_did(DidMethod::Key))
        .command(["db", "read"])
        .build(&root_signer)
        .await?;

    println!("Root Delegation Token:\n{}\n", root_delegation_str);

    // The user decodes and validates the received token before using it.
    let user_envelope = NucTokenEnvelope::decode(&root_delegation_str)?
        .validate_signatures()?;

    // === Step 3: User delegates to Service ===
    // The user creates a more constrained delegation for a specific service.
    // This new token inherits the subject and command from the proof.
    let user_to_service_delegation_str = NucTokenBuilder::extending(user_envelope)?
        .audience(service_keypair.to_did(DidMethod::Key))
        // The policy is reset, so we add a new, more specific one.
        .body(policy::op::eq(".args.id", json!(123)).into())
        .build(&user_signer)
        .await?;

    println!("User->Service Delegation Token:\n{}\n", user_to_service_delegation_str);

    // The service decodes and validates its token.
    let service_envelope = NucTokenEnvelope::decode(&user_to_service_delegation_str)?
        .validate_signatures()?;

    // === Step 4: Service creates an Invocation ===
    // The service invokes the capability to read user with id 123.
    let invocation_str = NucTokenBuilder::invocation(
        json!({ "collection": "users", "id": 123 }).as_object().unwrap().clone()
    )
        .proof(service_envelope)
        .audience(root_keypair.to_did(DidMethod::Key)) // The final receiver is the root resource server
        .subject(user_keypair.to_did(DidMethod::Key)) // Subject is inherited
        .command(["db", "read"]) // Command is inherited
        .build(&service_signer)
        .await?;

    println!("Final Invocation Token:\n{}\n", invocation_str);

    // === Step 5: Final Validation ===
    // The resource server receives the invocation and validates the entire chain.
    let final_envelope = NucTokenEnvelope::decode(&invocation_str)?
        .validate_signatures()?;

    let validator = NucValidator::new(ValidationConfig {
        // The validator must trust the root of the chain.
        root_issuers: vec![root_keypair.to_did(DidMethod::Key)],
        // The validator must know its own identity to check the audience.
        token_requirements: Some(policy::op::eq(
            ".aud",
            json!(root_keypair.to_did(DidMethod::Key).to_string()),
        )),
        // The validator can provide external context for policy evaluation.
        context: HashMap::new(),
        ..Default::default()
    });

    match validator.validate(&final_envelope) {
        Ok(_) => println!("✅ Final invocation chain is valid!"),
        Err(e) => println!("❌ Validation failed: {}", e),
    }

    Ok(())
}
```
