# Storage TTL policy

This document describes the storage TTL strategy used by the Credence Bond contract.

- `STORAGE_TTL_EXTEND_TO` (in `ours.rs`) is the configured "extend-to" TTL applied to
  long-lived `instance()` storage records (bonds and attestations). It is intentionally
  set to cover the maximum bond duration so that a bond locked for the maximum allowed
  duration does not expire before the owner can unlock it.

Key points

- On every read/write of long-lived bond/attestation records the contract calls:
  `e.storage().instance().extend_ttl(key, &STORAGE_TTL_EXTEND_TO)` via a small helper.
  This ensures hot records get their TTL bumped and remain accessible.

- The contract chooses `STORAGE_TTL_EXTEND_TO` so it is at least the maximum supported
  bond duration (365 days). This prevents silent archival of locked bonds.

Archival and recovery

- If an entry does become archived (e.g. due to an environment with a smaller
  `max_entry_ttl` or a missed TTL bump), the production recovery path is:
  - Admin intervention: the admin can restore critical entries from off-chain
    backups and write them back into contract `instance()` storage with a fresh TTL.
  - Alternatively, implement a dedicated `restore_*` helper that validates and
    writes archived entries (not included in this simplified repo).

Testing

- Unit tests (see `test.rs`) simulate ledger advancement via `Env::ledger().set(...)`
  and assert behaviour for TTL just below/above thresholds and for maximum-duration bonds.

Notes

- The Soroban runtime may clamp requested TTLs to the current ledger `max_entry_ttl`.
  Tests therefore explicitly set the ledger's `max_entry_ttl` to ensure deterministic behaviour.

- The chosen approach favors safety (preventing lost bonds) and predictable behaviour on hot paths.
