//! Replay attack prevention using per-identity nonces and deadline enforcement.
//!
//! Each identity has a nonce that must be included in state-changing calls.
//! The contract rejects replayed transactions by requiring nonce to match
//! the stored value, then incrementing it.
//!
//! Deadline enforcement ensures signatures cannot be used after expiry,
//! preventing long-lived replay windows. An optional grace window can be
//! configured by the admin to absorb minor ledger-inclusion delays near the
//! deadline boundary — it is DISABLED (0) by default.
//!
//! Domain binding ties each operation to the specific contract address,
//! blocking cross-contract replay.
//!
//! The nonce validation flow is atomic: deadline and contract-domain checks are
//! performed before the nonce is consumed, so stale or wrong-context signatures
//! do not advance the counter.
//!
//! Signed actions are bound to the current contract address; this prevents the
//! same nonce/deadline pair from replaying in a different contract context.

use soroban_sdk::{Address, Env};

use crate::DataKey;

/// Returns the current nonce for an identity.
#[must_use]
pub fn get_nonce(e: &Env, identity: &Address) -> u64 {
    e.storage()
        .instance()
        .get(&DataKey::Nonce(identity.clone()))
        .unwrap_or(0)
}

/// Checks that the provided nonce matches the current nonce, then increments it.
///
/// # Panics
/// Panics with "invalid nonce" if `expected_nonce` does not match stored nonce.
pub fn consume_nonce(e: &Env, identity: &Address, expected_nonce: u64) {
    let current = get_nonce(e, identity);
    if current != expected_nonce {
        panic!("invalid nonce: replay or out-of-order");
    }
    let next = current.checked_add(1).expect("nonce overflow");
    e.storage()
        .instance()
        .set(&DataKey::Nonce(identity.clone()), &next);
}

/// Returns the configured grace window in seconds (0 = strict enforcement).
///
/// Grace is DISABLED by default. When non-zero, signatures are accepted for
/// up to `grace` seconds past their nominal deadline to absorb inclusion delays.
/// Nonces are still consumed on first use — grace does NOT weaken replay protection.
fn get_grace_window(e: &Env) -> u64 {
    e.storage()
        .instance()
        .get(&DataKey::GraceWindow)
        .unwrap_or(0)
}

/// Validates that the current ledger timestamp is within the allowed window.
///
/// Accepted if: `now <= deadline + grace_window`
///
/// With default grace = 0 this is strictly `now <= deadline`.
///
/// # Panics
/// Panics with "signature expired" if the effective deadline has passed.
pub fn require_not_expired(e: &Env, deadline: u64) {
    let now = e.ledger().timestamp();
    let grace = get_grace_window(e);
    // saturating_add prevents u64 overflow on pathological deadline values
    let effective_deadline = deadline.saturating_add(grace);
    if now > effective_deadline {
        panic!("signature expired: deadline passed");
    }
}

/// Validates that the operation is bound to the current contract address.
///
/// This is the Soroban equivalent of EIP-712 domain separation: binding the
/// signed payload to a specific contract address prevents cross-contract replay
/// where a valid signature for contract A is submitted to contract B.
///
/// The current contract address is compared against the caller-provided
/// `contract_id` before the nonce is consumed.
///
/// # Panics
/// Panics with "domain mismatch" if `expected_contract` does not match the
/// current contract address.
pub fn require_domain_match(e: &Env, expected_contract: &Address) {
    let current = e.current_contract_address();
    if current != *expected_contract {
        panic!("domain mismatch: wrong contract address");
    }
}

/// Validate deadline (+ grace), domain, and consume nonce in one atomic call.
///
/// The order of checks is important:
/// 1. Deadline — fail fast on expired signatures before touching storage.
/// 2. Domain   — ensure the payload was bound to this contract address.
/// 3. Nonce    — prevent replay and enforce ordering.
///
/// If either deadline or domain validation fails, the nonce is not consumed.
pub fn validate_and_consume(
    e: &Env,
    identity: &Address,
    expected_contract: &Address,
    deadline: u64,
    nonce: u64,
) {
    require_not_expired(e, deadline);
    require_domain_match(e, expected_contract);
    consume_nonce(e, identity, nonce);
}

/// Variant of `validate_and_consume` that accepts an explicit grace window
/// (in seconds) instead of reading it from storage.
///
/// The `grace` parameter overrides the stored grace window for the deadline
/// check. All other checks (domain, nonce) behave identically.
#[allow(dead_code)]
pub fn validate_and_consume_with_grace(
    e: &Env,
    identity: &Address,
    expected_contract: &Address,
    deadline: u64,
    nonce: u64,
    grace: u64,
) {
    let now = e.ledger().timestamp();
    let effective_deadline = deadline.saturating_add(grace);
    if now > effective_deadline {
        panic!("signature expired: deadline passed");
    }
    require_domain_match(e, expected_contract);
    consume_nonce(e, identity, nonce);
}
