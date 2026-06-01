//! Tiered Bond System
//!
//! Assigns identity tiers (Bronze, Silver, Gold, Platinum) based on bonded amount thresholds.

use crate::BondTier;
use soroban_sdk::Env;

pub const TIER_BRONZE_MAX: i128 = 1_000_000_000_000_000_000_000;
pub const TIER_SILVER_MAX: i128 = 5_000_000_000_000_000_000_000;
pub const TIER_GOLD_MAX: i128 = 20_000_000_000_000_000_000_000;

#[must_use]
pub fn get_tier_for_amount(e: &Env, amount: i128) -> BondTier {
    let thresholds = e
        .storage()
        .instance()
        .get::<_, crate::TierThresholds>(&crate::DataKey::TierThresholds)
        .unwrap_or_else(|| crate::TierThresholds {
            bronze_max: TIER_BRONZE_MAX,
            silver_max: TIER_SILVER_MAX,
            gold_max: TIER_GOLD_MAX,
        });

    if amount < thresholds.bronze_max {
        BondTier::Bronze
    } else if amount < thresholds.silver_max {
        BondTier::Silver
    } else if amount < thresholds.gold_max {
        BondTier::Gold
    } else {
        BondTier::Platinum
    }
}

pub fn emit_tier_change_if_needed(
    e: &Env,
    identity: &soroban_sdk::Address,
    old_tier: BondTier,
    new_tier: BondTier,
) {
    if core::mem::discriminant(&old_tier) != core::mem::discriminant(&new_tier) {
        e.events().publish(
            (soroban_sdk::Symbol::new(e, "tier_changed"),),
            (identity.clone(), new_tier),
        );
    }
}
