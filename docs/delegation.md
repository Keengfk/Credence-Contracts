# Delegation System

Soroban contract enabling bond owners to delegate attestation and management rights to other addresses.

## Overview

The `CredenceDelegation` contract stores delegations keyed by `(owner, delegate, DelegationType)`. Each delegation carries a bounded expiry timestamp and can be revoked by the owner at any time.

## Types

### DelegationType

| Variant     | Description                                  |
| ----------- | -------------------------------------------- |
| Attestation | Delegate can attest on behalf of owner       |
| Management  | Delegate can manage bonds on behalf of owner |

### Delegation

| Field            | Type            | Description                      |
|------------------|-----------------|----------------------------------|
| owner            | Address         | Bond owner granting delegation   |
| delegate         | Address         | Address receiving delegated rights |
| delegation_type  | DelegationType  | Kind of delegation               |
| expires_at       | u64             | Ledger timestamp when delegation expires; must be in the allowed lifetime window |
| revoked          | bool            | Whether the delegation was revoked |

## Contract Functions

### `initialize(admin: Address)`

Set the contract admin. Can only be called once.

### `delegate(owner, delegate, delegation_type, expires_at) -> Delegation`

Create a delegation. Requires owner authorization. `expires_at` must be greater than the current ledger timestamp and no later than `now + MAX_DELEGATION_DURATION` (`365 days` by default). Emits a `delegation_created` event.

### `execute_delegated_delegate(owner, delegate, delegation_type, expires_at, payload) -> Delegation`

Create a delegation through a relayed, domain-separated payload. The same expiry bounds as `delegate` apply before nonce consumption, so over-long or already-expired requests cannot create a delegation or burn the owner's nonce.

### `revoke_delegation(owner, delegate, delegation_type)`

Revoke an active delegation. Requires owner authorization. Panics if the delegation does not exist or is already revoked. Emits a `delegation_revoked` event.

### `get_delegation(owner, delegate, delegation_type) -> Delegation`

Retrieve a stored delegation. Panics if not found.

### `is_valid_delegate(owner, delegate, delegation_type) -> bool`

Returns `true` if the delegation exists, is not revoked, and has not expired. Returns `false` otherwise (including when no delegation exists).

Delegations expire at the exact `expires_at` timestamp. A record with `expires_at == current_timestamp` is invalid.

## Events

| Event              | Data       | Emitted when               |
| ------------------ | ---------- | -------------------------- |
| delegation_created | Delegation | A new delegation is stored |
| delegation_revoked | Delegation | A delegation is revoked    |

## Security

- Only the owner can create or revoke their delegations (`require_auth`).
- Delegated payload verification normalizes all mismatch failures to `InvalidNonce` so callers do not learn which payload field differed.
- Delegations are time-bound; expired delegations are treated as invalid.
- Delegation lifetime is capped by `MAX_DELEGATION_DURATION` (`365 days`) to prevent never-expiring management or attestation authority.
- Owners may revoke expired delegations; the record remains invalid before and after revocation, and the explicit `revoked` flag preserves audit state.
- Double initialization is rejected.
- Double revocation is rejected.
- Each `(owner, delegate, type)` tuple maps to exactly one delegation record.

## Pausing

The contract implements a pause mechanism to protect the protocol in case of emergency.

- **Mechanism**: Can be a direct pause by admin (if threshold is 0) or a multi-sig proposal process (if threshold > 0).
- **Gated Functions**: All mutating functions related to delegation are gated and will panic if the contract is paused:
  - `delegate` / `execute_delegated_delegate`
  - `revoke_delegation` / `execute_delegated_revoke`
  - `revoke_attestation` / `execute_delegated_revoke_attest`
  - `invalidate_nonce_range`
- **Exempt Functions**: Query functions (`is_valid_delegate`, `get_delegation`, etc.) and pause-management functions remain active even when paused.

## Nonce Replay Model & Key Recovery

The contract enforces a uniform replay security model across all mutating entry points (`delegate`, `revoke_delegation`, `revoke_attestation`, and their `execute_delegated_*` relayer counterparts). Every identity maps directly to an independent sequential sequence stream.

1. **Direct Path Invocation**: Calls made directly by account owners must specify their current tracking sequence sequence parameter explicitly. This asserts operational parity with signed payloads.
2. **Relayed Executions**: Off-chain entities presenting payload structures must contain matching valid parameters and match the expected sequence sequence index exactly.
3. **Emergency Key Recovery**: Invoking `invalidate_nonce_range(id, to_nonce)` forces the internal sequence tracker forward. This permanently drops all signatures and pre-allocated instructions whose nonces fall below the updated boundary across both entry vectors.

## Usage

```bash
# Build
cargo build -p credence_delegation

# Test
cargo test -p credence_delegation
```

## Known Simplifications

Expired delegations are invalid and bounded at creation time, but they are not automatically cleaned up from storage. See [known-simplifications.md](known-simplifications.md#8-expired-delegations-are-not-auto-cleaned) for details and the production path.
