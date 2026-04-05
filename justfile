default: check-all

check-all: fmt clippy test

build:
    cargo build --workspace

test:
    cargo test --workspace

fmt:
    cargo fmt --all -- --check

fmt-fix:
    cargo fmt --all

clippy:
    cargo clippy --workspace -- -D warnings

audit:
    cargo audit

doc:
    cargo doc --workspace --no-deps --open
