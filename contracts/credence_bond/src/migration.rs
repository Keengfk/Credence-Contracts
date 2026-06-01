//! Storage migration utilities for IdentityBond
use soroban_sdk::Env;
use crate::{IdentityBond, DataKey};

/// Perform lazy migration of IdentityBond storage from v1 to v2 format.
///
/// This function reads the existing bond entry (if any) and writes it back
/// using the current `IdentityBond` definition.  Missing fields introduced in
/// v2 (`is_rolling`, `withdrawal_requested_at`, `notice_period_duration`)
/// will be populated with their default values (`false` and `0`).
///
/// The migration is idempotent and safe to call on every read; it only writes
/// when a bond is present.
pub fn migrate_v1_to_v2(e: &Env) {
    // The bond key is stored per‑identity; for lazy migration we need to
    // iterate over all keys. The SDK does not provide a direct iterator, so we
    // attempt to read a placeholder key. If the contract is called for a
    // specific identity (via other entrypoints) the migration will be triggered
    // there. Here we simply ensure the storage entry for the generic key is
    // upgraded if it exists.
    let key = DataKey::Bond; // Note: generic version used by get_identity_state
    if let Some(old_bond) = e.storage().instance().get::<_, IdentityBond>(&key) {
        // Write it back – the serialization will now include the new fields
        // with default values.
        e.storage().instance().set(&key, &old_bond);
    }
}
