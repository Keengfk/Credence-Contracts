//! Bond Creation Fee Mechanism
//!
//! Charges a configurable percentage of the bonded amount on creation, transfers
//! the fee to the protocol treasury, and supports fee waiver for certain conditions.
//! Emits fee collection events.

use soroban_sdk::{Address, Env, Symbol};

use crate::math;

/// Get treasury and fee rate (basis points). Returns (treasury, fee_bps).
/// If not set, fee is zero (no treasury = no fee).
pub fn get_config(e: &Env) -> (Option<Address>, u32) {
    let treasury: Option<Address> = e.storage().instance().get(&crate::DataKey::FeeTreasury);
    let fee_bps: u32 = e
        .storage()
        .instance()
        .get(&crate::DataKey::FeeBps)
        .unwrap_or(0);
    (treasury, fee_bps)
}

/// Set fee config. Admin only (enforced by caller). fee_bps in basis points (e.g. 100 = 1%).
pub fn set_config(e: &Env, treasury: Address, fee_bps: u32) {
    if fee_bps > math::BPS_DENOMINATOR as u32 {
        panic!("fee_bps must be <= {}", math::BPS_DENOMINATOR);
    }
    e.storage()
        .instance()
        .set(&crate::DataKey::FeeTreasury, &treasury);
    e.storage()
        .instance()
        .set(&crate::DataKey::FeeBps, &fee_bps);
}

/// Calculate fee for a bond amount. Returns (fee_amount, net_amount).
/// If fee is waived (e.g. fee_bps is 0 or waiver condition), fee is 0.
#[must_use]
pub fn calculate_fee(e: &Env, amount: i128) -> (i128, i128) {
    let (_treasury, fee_bps) = get_config(e);
    if fee_bps == 0 || amount <= 0 {
        return (0, amount);
    }
    math::split_bps(
        amount,
        fee_bps,
        "fee calculation overflow",
        "fee calculation div-by-zero",
        "fee calculation underflow",
    )
}

/// Check if fee is waived for this bond (e.g. zero amount, or future: whitelisted identity).
#[allow(dead_code)]
#[must_use]
pub fn is_fee_waived(e: &Env, amount: i128, _identity: &Address) -> bool {
    let (_, fee_bps) = get_config(e);
    fee_bps == 0 || amount <= 0
}

/// Record fee to the contract's fee pool (for later transfer to treasury).
/// In full implementation, transfer would happen here; we accumulate and emit event.
pub fn record_fee(e: &Env, identity: &Address, amount: i128, fee: i128, treasury: &Address) {
    if fee <= 0 {
        return;
    }
    let key = Symbol::new(e, "fees");
    let current: i128 = e.storage().instance().get(&key).unwrap_or(0);
    let new_total = math::add_i128(current, fee, "fee pool overflow");
    e.storage().instance().set(&key, &new_total);
    emit_fee_event(e, identity, amount, fee, treasury);
}

/// Emit fee collection event.
pub fn emit_fee_event(
    e: &Env,
    identity: &Address,
    bond_amount: i128,
    fee_amount: i128,
    treasury: &Address,
) {
    e.events().publish(
        (Symbol::new(e, "bond_creation_fee"),),
        (identity.clone(), bond_amount, fee_amount, treasury.clone()),
    );
}
