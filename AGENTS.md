# Repository Guidelines

This is an independent Rust repository under the UniClipboard umbrella workspace.

## Commands

Run `cargo fmt --check`, `cargo test`, and
`cargo clippy --all-targets --all-features -- -D warnings` before committing. Changes to container
packaging must also pass a local image build and health check.

## Architecture

Keep this project as a thin server around the upstream `iroh-relay` crate. Relay transport,
protocol handling, and connection lifecycle belong to upstream. This repository owns only
UniClipboard-specific configuration, access control, and deployment behavior.

Do not fork or copy upstream relay internals unless a documented upstream limitation leaves no
supported extension point.

## Security

Never accept access tokens as command-line values. Never log tokens, authorization headers, or
token-bearing URLs. Raw tokens must not be persisted by this application or retained in
application-owned authorization state after their digest has been computed. Credential files must
not be committed and, on Unix, must be readable only by their owner.

Use English for code, comments, documentation, commit messages, and pull request text.
Use AGPL-3.0-only for original project code.
