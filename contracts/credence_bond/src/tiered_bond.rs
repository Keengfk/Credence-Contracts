//! Tiered Bond System
//!
//! Assigns identity tiers (Bronze, Silver, Gold, Platinum) based on bonded amount thresholds.
//! Supports tier upgrade on bond increase and tier downgrade on partial withdrawal.
//! Emits tier change events when tier changes.
//!
//! # Important: Decimal Normalization
//! All thresholds are expressed in **normalized 18-decimal format**.
//! The bond contract normalizes all token amounts to 18 decimals on ingress,
//! so these thresholds work correctly regardless of the underlying token's decimals.
//!
//! Example thresholds (in normalized 18-decimal format):
//! - Bronze: < 1,000 tokens (1,000 * 10^18)
//! - Silver: >= 1,000 tokens, < 5,000 tokens
//! - Gold: >= 5,000 tokens, < 20,000 tokens  
//! - Platinum: >= 20,000 tokens

use crate::BondTier;
use soroban_sdk::Env;

/// Tier thresholds in normalized 18-decimal format.
/// These represent: Bronze < 1000, Silver < 5000, Gold < 20000 tokens
/// Assuming 18 decimals: 1000 * 10^18 = 10^21
pub const TIER_BRONZE_MAX: i128 = 1_000_000_000_000_000_000_000; // 1000 * 10^18
pub const TIER_SILVER_MAX: i128 = 5_000_000_000_000_000_000_000; // 5000 * 10^18
pub const TIER_GOLD_MAX: i128 = 20_000_000_000_000_000_000_000; // 20000 * 10^18

/// Returns the tier for a given bonded amount, checking for admin-configured storage thresholds.
///
/// # Boundary Inclusivity
/// - **Bronze**: [0, bronze_max) (Inclusive of 0, exclusive of bronze_max)
/// - **Silver**: [bronze_max, silver_max) (Inclusive of bronze_max, exclusive of silver_max)
/// - **Gold**: [silver_max, gold_max) (Inclusive of silver_max, exclusive of gold_max)
/// - **Platinum**: [gold_max, i128::MAX] (Inclusive of gold_max, inclusive of i128::MAX)
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

/// Emits a tier change event if the tier changed.
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
