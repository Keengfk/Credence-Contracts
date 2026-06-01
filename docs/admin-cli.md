# Admin CLI Documentation

This document provides usage instructions for the `credence-admin` command-line tool, which facilitates safe administrative operations on the Credence protocol.

## Installation

The CLI is built as part of the workspace. After building the project, the binary will be available at `target/debug/credence-admin`.

## General Usage

```sh
credence-admin [OPTIONS] <COMMAND>
```

- `--submit` – Execute the transaction on the network. Omit for a dry‑run (default).
- `--help` – Show help for the top‑level command or any subcommand.

## Subcommands

### Bond Set Early Exit Config

```sh
credence-admin bond-set-early-exit-config --bond-id <ID> --bps <BASIS_POINTS> [--submit]
```

Sets the early‑exit configuration for a specified bond.

### Bond Set Weights

```sh
credence-admin bond-set-weights --bond-id <ID> --weight <WEIGHT> [--submit]
```

Updates the weight configuration for a bond.

### Delegation Set Pause Signer

```sh
credence-admin delegation-set-pause-signer --delegation-id <ID> --signer <SIGNER> [--submit]
```

Configures the pause signer for a delegation.

## Dry‑Run Mode

When `--submit` is omitted, the CLI prints the XDR encoding of the transaction (Base64) without submitting it. This allows operators to verify the payload before execution.

## Examples

```sh
# Dry‑run setting early‑exit for bond "bond123" to 500 bps
credence-admin bond-set-early-exit-config --bond-id bond123 --bps 500

# Submit the same transaction
credence-admin bond-set-early-exit-config --bond-id bond123 --bps 500 --submit
```

## Testing

Run the integration tests to ensure XDR output matches snapshots:

```sh
cargo test -p credence_admin_cli
```

## Contributing

Add new subcommands by extending the `Commands` enum in `src/main.rs` and implementing corresponding handler functions.
