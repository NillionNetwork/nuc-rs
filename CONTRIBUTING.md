# Contributing

We welcome contributions to the project! Here's how you can get involved:

- 🐛 Report bugs and submit feature requests
- 🔧 Submit pull requests
- 📖 Improve documentation
- 💬 Join discussions
- ⭐ Star the repository

## Development

To get started, install [Rust](https://www.rust-lang.org/) and ensure all tests and lints pass by running:

```bash
cargo test
cargo clippy -- -D warnings
```

## Test Input Generation

To generate a set of test assertions that can be used by other NUC implementations (like `nuc-ts`) to ensure compatibility, run tests with the `NUC_VALIDATOR_LOG_ASSERTIONS` environment variable set:

```bash
NUC_VALIDATOR_LOG_ASSERTIONS=1 cargo test -q -- --nocapture > assertions.txt
```

This will create the file `assertions.txt` containing all test assertions in a machine-readable format.

## Versioning

The version number format for this crate conforms with [Semantic Versioning 2.0.0](https://semver.org/#semantic-versioning-200).

## Publishing

This library can be published as a [crate on crates.io](https://crates.io/) via standard Cargo commands. This process is typically automated through CI/CD workflows.
