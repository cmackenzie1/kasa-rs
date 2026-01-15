.PHONY: fmt clippy test

fmt:
	cargo fmt

clippy:
	cargo clippy -- -D warnings

test:
	cargo test
