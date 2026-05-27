# Bond Gas Benchmarks

> Soroban SDK v22.0.10. Source-level storage profile for `ours.rs`.
> Date: 2026-05-27.

This document records the storage/resource budget for the bond withdrawal and
slashing hot paths touched by #369. The current checked-in workspace does not
compile `ours.rs` as the active `credence_bond` crate, so these numbers are
source-level storage operation counts rather than Soroban CPU/memory fee units.
They are still the right optimization target for these paths because Soroban
resource fees are dominated by storage host operations.

## Scope

Profiled paths:

- `withdraw_early`
- `withdraw_bond`
- `slash_bond`

Optimization goals:

- Read each storage key at most once per call.
- Mutate the loaded `IdentityBond` in place.
- Write the bond key once.
- Preserve auth, lock-up, slashing, overflow, and reentrancy checks.
- Keep checks-effects-interactions ordering before optional callback calls.

## Storage Operation Budget

Counts below are success-path storage operations by key. `extend_ttl` is listed
separately because it is a storage host operation but does not reload the bond.

| Function | Key | Before | After | Change |
| --- | --- | ---: | ---: | ---: |
| `withdraw_early` | `Bond` read | 1 | 1 | 0 |
| `withdraw_early` | `Bond` write | 1 | 1 | 0 |
| `withdraw_early` | `Bond` TTL bump | 2 | 2 | 0 |
| `withdraw_early` | early-exit config read | 1 | 1 | 0 |
| `withdraw_bond` | `Bond` read | 1 | 1 | 0 |
| `withdraw_bond` | `Bond` write | 1 | 1 | 0 |
| `withdraw_bond` | `Bond` TTL bump | 4 | 2 | -2 |
| `withdraw_bond` | lock read | 1 | 1 | 0 |
| `withdraw_bond` | lock write | 2 | 2 | 0 |
| `withdraw_bond` | callback read | 1 | 1 | 0 |
| `slash_bond` | `Admin` read | 1 | 1 | 0 |
| `slash_bond` | `Bond` read | 1 | 1 | 0 |
| `slash_bond` | `Bond` write | 1 | 1 | 0 |
| `slash_bond` | lock read | 1 | 1 | 0 |
| `slash_bond` | lock write | 2 | 2 | 0 |
| `slash_bond` | callback read | 1 | 1 | 0 |

## Structural Changes

| Path | Before | After |
| --- | --- | --- |
| `withdraw_early` | Local available-balance calculation in the function body | Shared checked available-balance helper; no additional storage reads |
| `withdraw_bond` | Constructed a new full `IdentityBond` literal and duplicated fields | Mutates the loaded `IdentityBond` in place, then writes once |
| `withdraw_bond` | Bumped the bond TTL twice after read and twice after write | Bumps once after read and once after write |
| `withdraw_bond` | Used unchecked `bonded_amount - slashed_amount` | Uses checked subtraction and preserves lock release on error |
| `slash_bond` | Constructed a new full `IdentityBond` literal and duplicated fields | Mutates `slashed_amount` on the loaded bond, then writes once |
| `slash_bond` | Used unchecked addition for `slashed_amount + slash_amount` | Uses checked addition and rejects non-positive slash amounts |

## Budget Constants

`ours.rs` now exposes source-level budget constants:

- `WITHDRAW_EARLY_STORAGE_BUDGET`
- `WITHDRAW_BOND_STORAGE_BUDGET`
- `SLASH_BOND_STORAGE_BUDGET`

The accompanying `gas_profile_tests` module asserts that each hot path remains
read-once/write-once for the bond key. These tests are intentionally simple
static guards so future edits cannot silently raise the declared storage budget.

## Reproduction Notes

Run the normal test suite:

```bash
cargo test --workspace
```

This passed on 2026-05-27 after restoring the workspace test prerequisites for
the active crates. The `ours.rs` bond implementation remains a root-level source
snapshot rather than the active `credence_bond` crate, so the numbers above are
the reproducible source-level baseline for #369 until that implementation is
reattached to the workspace and Soroban CPU/memory budget tests can be collected
with `env.budget()`.
