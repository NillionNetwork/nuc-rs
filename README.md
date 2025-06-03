# nuc-rs

A Rust crate to create and validate NUCs, the authentication mechanism used in [Nillion](https://nillion.com/)'s blind 
modules.

# Contributing

In order to contribute, install [Rust](https://www.rust-lang.org/) and ensure all tests and lints pass by running:

```bash
cargo test
cargo clippy
```

## Test input generation

In order to generate test inputs that can be used in other implementations of NUC libraries to ensure all 
implementations consider the same tokens as valid/invalid, run tests like this:

```bash
NUC_VALIDATOR_LOG_ASSERTIONS=1 cargo test -q 2>/tmp/assertions.txt
```

This will create the file `/tmp/assertions.txt` containing all the test assertions.

