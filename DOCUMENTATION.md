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
    builder::{DelegationBuilder, InvocationBuilder},
    did::Did,
    envelope::NucTokenEnvelope,
    keypair::Keypair,
    policy,
    signer::DidMethod,
    validator::{ValidationParameters, TokenTypeRequirements, NucValidator},
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
    let root_delegation_str = DelegationBuilder::new()
        .policy(policy::op::eq(".command", json!("/db/read")))
        .policy(policy::op::eq(".args.collection", json!("users")))
        .audience(user_keypair.to_did(DidMethod::Key))
        .subject(user_keypair.to_did(DidMethod::Key))
        .command(["db", "read"])
        .sign_and_serialize(&root_signer)
        .await?;

    println!("Root Delegation Token:\n{}\n", root_delegation_str);

    // === Step 3: User delegates to Service ===
    // The user creates a more constrained delegation for a specific service.
    // This new token inherits the subject and command from the proof.
    let user_to_service_delegation_str = DelegationBuilder::extending_from_serialized(&root_delegation_str)?
        .audience(service_keypair.to_did(DidMethod::Key))
        // The policy is reset, so we add a new, more specific one.
        .policy(policy::op::eq(".args.id", json!(123)))
        .sign_and_serialize(&user_signer)
        .await?;

    println!("User->Service Delegation Token:\n{}\n", user_to_service_delegation_str);

    // === Step 4: Service creates an Invocation ===
    // The service invokes the capability to read user with id 123.
    let invocation_str = InvocationBuilder::extending_from_serialized(&user_to_service_delegation_str)?
        .arguments(json!({ "collection": "users", "id": 123 }))
        .audience(root_keypair.to_did(DidMethod::Key)) // The final receiver is the root resource server
        .sign_and_serialize(&service_signer)
        .await?;

    println!("Final Invocation Token:\n{}\n", invocation_str);

    // === Step 5: Final Validation ===
    // The resource server receives the invocation and validates the entire chain.
    let final_envelope = NucTokenEnvelope::decode(&invocation_str)?
        .validate_signatures()?;

    let root_keys = vec![root_keypair.public_key()];
    let mut validator = NucValidator::new(&root_keys);
    let parameters = ValidationParameters {
        token_requirements: TokenTypeRequirements::Invocation(root_keypair.to_did(DidMethod::Key)),
        ..Default::default()
    };
    let context = HashMap::new();

    match validator.validate(final_envelope, parameters, &context) {
        Ok(_) => println!("✅ Final invocation chain is valid!"),
        Err(e) => println!("❌ Validation failed: {}", e),
    }

    Ok(())
}
```
