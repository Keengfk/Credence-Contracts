//! Early-exit penalty helpers for the Credence Bond contract.
//!
//! # Basis-point semantics
//! `penalty_bps` is an integer in the range `[0, 10_000]` where 10_000 = 100%.
//! Values outside this range are rejected by [`set_config`].
//!
//! # Penalty clamping
//! [`calculate_penalty`] guarantees the returned penalty is **at most** `amount`
//! so the user always receives a non-negative net amount.

use credence_errors::ContractError;
use soroban_sdk::{contracttype, panic_with_error, Address, Env, Symbol};

/// Maximum allowed value for `penalty_bps` (100 % in basis points).
pub const MAX_PENALTY_BPS: u32 = 10_000;

// ---------------------------------------------------------------------------
// Storage key
// ---------------------------------------------------------------------------

#[contracttype]
enum DataKey {
    EarlyExitConfig,
}

// ---------------------------------------------------------------------------
// On-chain config type
// ---------------------------------------------------------------------------

/// Persistent early-exit configuration.
#[contracttype]
#[derive(Clone, Debug)]
pub struct EarlyExitConfig {
    /// Address that receives penalty amounts.
    pub treasury: Address,
    /// Penalty rate in basis points (0 – 10 000; 10 000 = 100 %).
    pub penalty_bps: u32,
}

// ---------------------------------------------------------------------------
// Public helpers
// ---------------------------------------------------------------------------

/// Store (or overwrite) the early-exit configuration.
///
/// # Errors
/// - [`ContractError::InvalidPenaltyBps`] when `penalty_bps > 10_000`.
///
/// # Events
/// Emits `"early_exit_cfg_set"` with `(old_penalty_bps, new_penalty_bps, treasury)`.
/// If no previous config exists, `old_penalty_bps` is `0`.
pub fn set_config(e: &Env, treasury: Address, penalty_bps: u32) {
    // --- Validate penalty_bps <= 10_000 (100 %) ---
    if penalty_bps > MAX_PENALTY_BPS {
        panic_with_error!(e, ContractError::InvalidPenaltyBps);
    }

    // Read old config for event (default to 0 / zero-address if unset).
    let old_penalty_bps: u32 = e
        .storage()
        .instance()
        .get::<_, EarlyExitConfig>(&DataKey::EarlyExitConfig)
        .map(|c| c.penalty_bps)
        .unwrap_or(0);

    let cfg = EarlyExitConfig {
        treasury: treasury.clone(),
        penalty_bps,
    };
    e.storage()
        .instance()
        .set(&DataKey::EarlyExitConfig, &cfg);

    // Emit config-changed event with old and new values.
    e.events().publish(
        (Symbol::new(e, "early_exit_cfg_set"),),
        (old_penalty_bps, penalty_bps, treasury),
    );
}

/// Load the stored early-exit config.
///
/// # Errors
/// - [`ContractError::EarlyExitConfigNotSet`] if [`set_config`] was never called.
///
/// # Returns
/// `(treasury, penalty_bps)`
pub fn get_config(e: &Env) -> (Address, u32) {
    let cfg: EarlyExitConfig = e
        .storage()
        .instance()
        .get(&DataKey::EarlyExitConfig)
        .unwrap_or_else(|| panic_with_error!(e, ContractError::EarlyExitConfigNotSet));
    (cfg.treasury, cfg.penalty_bps)
}

/// Compute the time-decayed early-exit penalty.
///
/// Formula:
/// ```text
/// penalty = (amount × penalty_bps / 10_000) × (remaining / duration)
/// ```
///
/// The result is **clamped** to `[0, amount]` so the user's net is always ≥ 0
/// and to guard against any edge-case where rounding could exceed the full amount.
///
/// # Parameters
/// - `amount`      — tokens being withdrawn (must be ≥ 0; caller enforces this).
/// - `remaining`   — seconds left until lock-up end.
/// - `duration`    — total bond duration in seconds.
/// - `penalty_bps` — penalty rate (0 – 10 000; enforced by [`set_config`]).
///
/// # Returns
/// Penalty in the same unit as `amount`, guaranteed `<= amount`.
pub fn calculate_penalty(amount: i128, remaining: u64, duration: u64, penalty_bps: u32) -> i128 {
    if duration == 0 || penalty_bps == 0 || amount <= 0 {
        return 0;
    }

    // Scale factor: (amount * penalty_bps * remaining) / (10_000 * duration)
    // Use i128 arithmetic throughout; all inputs fit comfortably.
    let numerator = amount
        .saturating_mul(penalty_bps as i128)
        .saturating_mul(remaining as i128);
    let denominator = (MAX_PENALTY_BPS as i128).saturating_mul(duration as i128);

    let penalty = numerator / denominator;

    // Clamp: penalty must never exceed the withdrawn amount.
    penalty.min(amount).max(0)
}

/// Emit the `"early_exit_penalty"` event.
///
/// Fields: `(identity, withdraw_amount, penalty_amount, treasury)`.
pub fn emit_penalty_event(
    e: &Env,
    identity: &Address,
    withdraw_amount: i128,
    penalty_amount: i128,
    treasury: &Address,
) {
    e.events().publish(
        (Symbol::new(e, "early_exit_penalty"),),
        (identity.clone(), withdraw_amount, penalty_amount, treasury.clone()),
    );
}
