# Service Documentation

## Building

You can build the `nilauth` binary from source using Cargo:

```bash
cargo build --release
```

The resulting binary will be located at `target/release/nilauth`.

## Configuration

The service is configured using a YAML file (e.g., `config.yaml`) and/or environment variables. See `config.sample.yaml` for a complete example.

| Section           | Key                         | Environment Variable                                          | Description                                                     |
|:------------------|:----------------------------|:--------------------------------------------------------------|:----------------------------------------------------------------|
| **`server`**      | `bind_endpoint`             | `NILAUTH__SERVER__BIND_ENDPOINT`                              | The `ip:port` for the main API server to listen on.             |
| **`private_key`** | `hex`                       | `NILAUTH__PRIVATE_KEY__HEX`                                   | The 32-byte secp256k1 private key in hex for the service.       |
| **`metrics`**     | `bind_endpoint`             | `NILAUTH__METRICS__BIND_ENDPOINT`                             | The `ip:port` for the Prometheus metrics server.                |
| **`payments`**    | `nilchain_url`              | `NILAUTH__PAYMENTS__NILCHAIN_URL`                             | The JSON-RPC URL of a Nillion Chain node.                       |
|                   | `renewal_threshold_seconds` | `NILAUTH__PAYMENTS__SUBSCRIPTIONS__RENEWAL_THRESHOLD_SECONDS` | How close to expiration a subscription must be to be renewable. |
|                   | `length_seconds`            | `NILAUTH__PAYMENTS__SUBSCRIPTIONS__LENGTH_SECONDS`            | The duration of a newly purchased subscription.                 |
|                   | `dollar_cost`               | -                                                             | A map of blind modules (`nildb`, `nilai`) to their cost in USD. |
|                   | `base_url`                  | `NILAUTH__PAYMENTS__TOKEN_PRICE__BASE_URL`                    | The base URL for the token price API (e.g., CoinGecko).         |
| **`postgres`**    | `url`                       | `NILAUTH__POSTGRES__URL`                                      | The connection string for the PostgreSQL database.              |

To run the service with a config file:

```bash
./target/release/nilauth --config-file config.yaml
```

## Running with Docker

A `Dockerfile` and `docker-compose.yml` are provided for containerized deployment. To run the service and its dependencies (PostgreSQL, nilchaind devnet):

```bash
docker compose up
```

Once running, you can start the `nilauth` service locally, and it will connect to the containerized dependencies as defined in `config.sample.yaml`.

## API Endpoints

The service exposes a RESTful API for managing subscriptions and minting tokens. The complete OpenAPI specification is available at the `/openapi.json` endpoint of a running instance.

Key endpoints include:

- `GET /about`: Get information about the service instance.
- `GET /api/v1/payments/cost`: Get the current cost of a subscription.
- `POST /api/v1/payments/validate`: Validate an on-chain payment to grant a subscription.
- `GET /api/v1/subscriptions/status`: Check the status of a subscription.
- `POST /api/v1/nucs/create`: Mint a root NUC for an active subscription.
- `POST /api/v1/revocations/revoke`: Revoke a previously issued NUC.
- `POST /api/v1/revocations/lookup`: Check if a NUC in a chain has been revoked.
