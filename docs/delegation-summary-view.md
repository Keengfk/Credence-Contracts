# Delegation Summary View

The `get_delegation_summary` view function provides a comprehensive summary of a delegation's state for indexers and off-chain tools.

## Entrypoint

```rust
pub fn get_delegation_summary(
    e: Env,
    owner: Address,
    delegate: Address,
    delegation_type: DelegationType,
) -> DelegationSummary
```

## `DelegationSummary` Struct

| Field | Type | Description |
|-------|------|-------------|
| `is_valid` | `bool` | `true` if the delegation is NOT revoked AND the current ledger timestamp is less than `expires_at`. |
| `time_to_expiry` | `u64` | The remaining lifetime of the delegation in seconds (`expires_at - now`). Returns 0 if expired. |
| `delegation_type` | `DelegationType` | The type of delegation (`Attestation` or `Management`). |
| `revoked_at` | `u64` | The timestamp when the delegation was revoked. Currently returns 0 as it is not persisted in storage. |
| `scheme` | `u8` | The signature scheme used to create the delegation. Currently returns 0 (Ed25519) as it is not persisted in storage. |

## Usage for Indexers

Indexers should use this view to track the validity and remaining lifetime of delegations without needing to implement the expiration logic locally.

> [!NOTE]
> This is a read-only view and does not require authentication. it utilizes `e.storage().persistent().get` and does not call `require_auth()`.
