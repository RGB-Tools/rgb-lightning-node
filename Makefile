.PHONY: help build build-cli build-release build-cli-release test check clean install install-cli run-node run-cli demo

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'

build: ## Build the RGB Lightning Node (debug)
	cargo build --bin rgb-lightning-node

build-cli: ## Build the CLI (debug)
	cargo build --bin rln-cli

build-release: ## Build the RGB Lightning Node (release)
	cargo build --release --bin rgb-lightning-node

build-cli-release: ## Build the CLI (release)
	cargo build --release --bin rln-cli

build-all: build-release build-cli-release ## Build both node and CLI (release)

test: ## Run tests
	cargo test

check: ## Check code (without building)
	cargo check --all-targets

check-cli: ## Check CLI code
	cargo check --bin rln-cli

clean: ## Clean build artifacts
	cargo clean

install: build-release ## Install RGB Lightning Node
	cargo install --path . --bin rgb-lightning-node

install-cli: build-cli-release ## Install CLI
	cargo install --path . --bin rln-cli

install-all: ## Install both node and CLI
	cargo install --path . --bin rgb-lightning-node
	cargo install --path . --bin rln-cli

run-node: ## Run RGB Lightning Node (requires arguments)
	@echo "Usage: make run-node ARGS='<storage-dir> [options]'"
	@echo "Example: make run-node ARGS='./data --network testnet'"
	cargo run --bin rgb-lightning-node -- $(ARGS)

run-cli: ## Run CLI (requires command)
	@echo "Usage: make run-cli CMD='<command>'"
	@echo "Example: make run-cli CMD='node info'"
	cargo run --bin rln-cli -- $(CMD)

demo: build-cli-release ## Run CLI demo script
	@echo "Running CLI demo..."
	@./examples/cli_demo.sh

clippy: ## Run clippy linter
	cargo clippy --all-targets -- -D warnings

fmt: ## Format code
	cargo fmt --all

fmt-check: ## Check code formatting
	cargo fmt --all -- --check

doc: ## Generate documentation
	cargo doc --no-deps --open

# Development helpers
dev-node: ## Run node in development mode (with example data dir)
	@mkdir -p ./dev-data
	cargo run --bin rgb-lightning-node -- ./dev-data --network regtest

# CLI convenience targets
cli-help: build-cli ## Show CLI help
	cargo run --bin rln-cli -- --help

cli-version: build-cli ## Show CLI version
	cargo run --bin rln-cli -- --version

# Quick CLI commands (assumes node is running on localhost:3001)
cli-node-info: build-cli ## Get node info
	cargo run --bin rln-cli -- node info

cli-list-assets: build-cli ## List RGB assets
	cargo run --bin rln-cli -- rgb list-assets

cli-list-channels: build-cli ## List Lightning channels
	cargo run --bin rln-cli -- channel list

cli-list-peers: build-cli ## List Lightning peers
	cargo run --bin rln-cli -- peer list

cli-list-payments: build-cli ## List Lightning payments
	cargo run --bin rln-cli -- payment list

cli-btc-balance: build-cli ## Get BTC balance
	cargo run --bin rln-cli -- onchain btc-balance

# Installation check
check-install: ## Check if binaries are installed
	@which rgb-lightning-node && echo "✓ rgb-lightning-node is installed" || echo "✗ rgb-lightning-node not found"
	@which rln-cli && echo "✓ rln-cli is installed" || echo "✗ rln-cli not found"

# Create example directory structure
setup-example: ## Set up example directory structure
	@mkdir -p examples
	@mkdir -p dev-data
	@echo "✓ Created example directories"

# Release build for distribution
release: clean build-all ## Create release builds
	@echo "✓ Release builds created:"
	@ls -lh target/release/rgb-lightning-node
	@ls -lh target/release/rln-cli

