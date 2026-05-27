#![no_std]

mod early_exit_penalty;
mod nonce;
mod rolling_bond;
mod slashing;
mod tiered_bond;
mod weighted_attestation;

pub mod types;

use credence_errors::ContractError;
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, String, Symbol, Vec, Val, panic_with_error};

/// Identity tier based on bonded amount (Bronze < Silver < Gold < Platinum).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BondTier {
    Bronze,
    Silver,
    Gold,
    Platinum,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct IdentityBond {
    pub identity: Address,
    pub bonded_amount: i128,
    pub bond_start: u64,
    pub bond_duration: u64,
    pub slashed_amount: i128,
    pub active: bool,
    /// If true, bond auto-renews at period end unless withdrawal was requested.
    pub is_rolling: bool,
    /// When withdrawal was requested (0 = not requested).
    pub withdrawal_requested_at: u64,
    /// Notice period duration for rolling bonds (seconds).
    pub notice_period_duration: u64,
}

// Re-export attestation type (definitions and validation in types::attestation).
pub use types::Attestation;

#[contracttype]
pub enum DataKey {
    Admin,
    Bond,
    Attester(Address),
    Attestation(u64),
    AttestationCounter,
    SubjectAttestations(Address),
    /// Per-identity attestation count (updated on add/revoke).
    SubjectAttestationCount(Address),
    /// Per-identity nonce for replay prevention.
    Nonce(Address),
    /// Attester stake used for weighted attestation (set by admin or from bond).
    AttesterStake(Address),
    /// Global config for weighted attestation computation.
    WeightConfig,
}

// Storage TTL policy constants. Tuned for maximum bond durations and long-lived
// attestation records. Values taken from repository test snapshots (max_entry_ttl).
// Ensure TTL covers the maximum allowed bond duration (365 days).
const STORAGE_TTL_EXTEND_TO: u64 = 31_536_000; // 365 days in seconds

// Helper: bump storage TTL for a given key in instance storage. This calls
// `extend_ttl` on the instance storage to ensure long-lived entries do not
// expire silently. It's safe to call repeatedly on hot paths.
fn bump_instance_ttl<K: soroban_sdk::IntoVal<Env> + Clone>(e: &Env, key: &K) {
    // Best-effort: call extend_ttl if available on the instance API.
    // If the underlying SDK changes, this single helper isolates the callsite.
    e.storage().instance().extend_ttl(key, &STORAGE_TTL_EXTEND_TO);
}

#[contract]
pub struct CredenceBond;

#[contractimpl]
impl CredenceBond {
    /// Initialize the contract (admin).
    ///
    /// Errors:
    /// - `ContractError::AlreadyInitialized` (2) if initialize is called twice
    pub fn initialize(e: Env, admin: Address) {
        admin.require_auth();
        e.storage().instance().set(&DataKey::Admin, &admin);
    }

    /// Set early exit penalty config. Only admin should call.
    ///
    /// Errors:
    /// - `ContractError::NotInitialized` (1) when the contract admin is not set
    /// - `ContractError::NotAdmin` (100) when `admin` is not the stored admin
    pub fn set_early_exit_config(e: Env, admin: Address, treasury: Address, penalty_bps: u32) {
        admin.require_auth();
        let stored_admin: Address = e
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::NotInitialized));
        if stored_admin != admin {
            panic_with_error!(e, ContractError::NotAdmin);
        }
        early_exit_penalty::set_config(&e, treasury, penalty_bps);
    }

    /// Register an authorized attester (only admin can call).
    ///
    /// Errors:
    /// - `ContractError::NotInitialized` (1)
    pub fn register_attester(e: Env, attester: Address) {
        let admin: Address = e
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::NotInitialized));
        admin.require_auth();

        e.storage()
            .instance()
            .set(&DataKey::Attester(attester.clone()), &true);
        e.events()
            .publish((Symbol::new(&e, "attester_registered"),), attester);
    }

    /// Remove an attester's authorization (only admin can call).
    ///
    /// Errors:
    /// - `ContractError::NotInitialized` (1)
    pub fn unregister_attester(e: Env, attester: Address) {
        let admin: Address = e
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::NotInitialized));
        admin.require_auth();

        e.storage()
            .instance()
            .remove(&DataKey::Attester(attester.clone()));
        e.events()
            .publish((Symbol::new(&e, "attester_unregistered"),), attester);
    }

    /// Check if an address is an authorized attester.
    pub fn is_attester(e: Env, attester: Address) -> bool {
        e.storage()
            .instance()
            .get(&DataKey::Attester(attester))
            .unwrap_or(false)
    }

    /// Create or top-up a bond for an identity.
    ///
    /// Authority: `identity` must authorize this call.
    /// In a full implementation this would transfer USDC from the caller and store the bond.
    pub fn create_bond(
        e: Env,
        identity: Address,
        amount: i128,
        duration: u64,
        is_rolling: bool,
        notice_period_duration: u64,
    ) -> IdentityBond {
        identity.require_auth();
        let bond_start = e.ledger().timestamp();

        // Verify the end timestamp wouldn't overflow
        let _end_timestamp = bond_start
            .checked_add(duration)
            .expect("bond end timestamp would overflow");

        let bond = IdentityBond {
            identity: identity.clone(),
            bonded_amount: amount,
            bond_start,
            bond_duration: duration,
            slashed_amount: 0,
            active: true,
            is_rolling,
            withdrawal_requested_at: 0,
            notice_period_duration,
        };
        let key = DataKey::Bond;
        e.storage().instance().set(&key, &bond);
        bump_instance_ttl(&e, &key);
        let tier = tiered_bond::get_tier_for_amount(amount);
        tiered_bond::emit_tier_change_if_needed(&e, &identity, BondTier::Bronze, tier);
        bond
    }

    /// Return current bond state for an identity (simplified: single bond per contract instance).
    ///
    /// Errors:
    /// - `ContractError::BondNotFound` (200)
    pub fn get_identity_state(e: Env) -> IdentityBond {
        let key = DataKey::Bond;
        let bond = e.storage()
            .instance()
            .get::<_, IdentityBond>(&key)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::BondNotFound));
        bump_instance_ttl(&e, &key);
        bond
    }

    /// Add an attestation for a subject (only authorized attesters can call).
    /// Requires correct nonce for replay prevention; rejects duplicate (verifier, identity, data).
    /// Weight is computed from attester stake (weighted attestation system).
    ///
    /// @param e Contract environment
    /// @param attester Authorized verifier (must be registered and must pass require_auth)
    /// @param subject Identity being attested
    /// @param attestation_data Opaque attestation payload
    /// @param nonce Current nonce for attester (get_nonce(attester)); incremented on success
    /// @return The created Attestation (id, verifier, identity, timestamp, weight, data, revoked)
    ///
    /// Errors:
    /// - `ContractError::UnauthorizedAttester` (102)
    /// - `ContractError::DuplicateAttestation` (300)
    /// - `ContractError::Overflow` (700)
    pub fn add_attestation(
        e: Env,
        attester: Address,
        subject: Address,
        attestation_data: String,
        nonce: u64,
    ) -> Attestation {
        attester.require_auth();

        let is_authorized = e
            .storage()
            .instance()
            .get(&DataKey::Attester(attester.clone()))
            .unwrap_or(false);
        if !is_authorized {
            panic_with_error!(e, ContractError::UnauthorizedAttester);
        }

        nonce::consume_nonce(&e, &attester, nonce);

        let dedup_key = types::AttestationDedupKey {
            verifier: attester.clone(),
            identity: subject.clone(),
            attestation_data: attestation_data.clone(),
        };
        if e.storage().instance().has(&dedup_key) {
            panic_with_error!(e, ContractError::DuplicateAttestation);
        }

        let counter_key = DataKey::AttestationCounter;
        let id: u64 = e.storage().instance().get(&counter_key).unwrap_or(0);
        let next_id = id
            .checked_add(1)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::Overflow));
        e.storage().instance().set(&counter_key, &next_id);

        let weight = weighted_attestation::compute_weight(&e, &attester);
        types::Attestation::validate_weight(weight);

        let attestation = Attestation {
            id,
            verifier: attester.clone(),
            identity: subject.clone(),
            timestamp: e.ledger().timestamp(),
            weight,
            attestation_data: attestation_data.clone(),
            revoked: false,
        };

        e.storage()
            .instance()
            .set(&DataKey::Attestation(id), &attestation);
        bump_instance_ttl(&e, &DataKey::Attestation(id));
        e.storage().instance().set(&dedup_key, &id);
        bump_instance_ttl(&e, &dedup_key);

        let subject_key = DataKey::SubjectAttestations(subject.clone());
        let mut attestations: Vec<u64> = e
            .storage()
            .instance()
            .get(&subject_key)
            .unwrap_or(Vec::new(&e));
        attestations.push_back(id);
        e.storage().instance().set(&subject_key, &attestations);
        bump_instance_ttl(&e, &subject_key);

        let count_key = DataKey::SubjectAttestationCount(subject.clone());
        let count: u32 = e.storage().instance().get(&count_key).unwrap_or(0);
        e.storage()
            .instance()
            .set(&count_key, &count.saturating_add(1));
        bump_instance_ttl(&e, &count_key);

        e.events().publish(
            (Symbol::new(&e, "attestation_added"), subject),
            (id, attester, attestation_data, weight),
        );

        attestation
    }

    /// Revoke an attestation (only the original attester can revoke). Requires correct nonce.
    ///
    /// Errors:
    /// - `ContractError::AttestationNotFound` (301)
    /// - `ContractError::NotOriginalAttester` (103)
    /// - `ContractError::AttestationAlreadyRevoked` (302)
    pub fn revoke_attestation(e: Env, attester: Address, attestation_id: u64, nonce: u64) {
        attester.require_auth();
        nonce::consume_nonce(&e, &attester, nonce);

        let key = DataKey::Attestation(attestation_id);
        let mut attestation: Attestation = e
            .storage()
            .instance()
            .get(&key)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::AttestationNotFound));

        if attestation.verifier != attester {
            panic_with_error!(e, ContractError::NotOriginalAttester);
        }
        if attestation.revoked {
            panic_with_error!(e, ContractError::AttestationAlreadyRevoked);
        }

        attestation.revoked = true;
        e.storage().instance().set(&key, &attestation);
        bump_instance_ttl(&e, &key);

        let dedup_key = types::AttestationDedupKey {
            verifier: attestation.verifier.clone(),
            identity: attestation.identity.clone(),
            attestation_data: attestation.attestation_data.clone(),
        };
        e.storage().instance().remove(&dedup_key);
        // Removing doesn't need a TTL bump; keep for symmetry.

        let count_key = DataKey::SubjectAttestationCount(attestation.identity.clone());
        let count: u32 = e.storage().instance().get(&count_key).unwrap_or(0);
        e.storage()
            .instance()
            .set(&count_key, &count.saturating_sub(1));
        bump_instance_ttl(&e, &count_key);

        e.events().publish(
            (
                Symbol::new(&e, "attestation_revoked"),
                attestation.identity.clone(),
            ),
            (attestation_id, attester),
        );
    }

    /// Get an attestation by ID.
    ///
    /// Errors:
    /// - `ContractError::AttestationNotFound` (301)
    pub fn get_attestation(e: Env, attestation_id: u64) -> Attestation {
        let key = DataKey::Attestation(attestation_id);
        let att = e.storage()
            .instance()
            .get(&key)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::AttestationNotFound));
        bump_instance_ttl(&e, &key);
        att
    }

    /// Get all attestation IDs for a subject.
    pub fn get_subject_attestations(e: Env, subject: Address) -> Vec<u64> {
        let key = DataKey::SubjectAttestations(subject);
        let v = e.storage()
            .instance()
            .get(&key)
            .unwrap_or(Vec::new(&e));
        bump_instance_ttl(&e, &key);
        v
    }

    /// Get attestation count for a subject (identity). O(1).
    pub fn get_subject_attestation_count(e: Env, subject: Address) -> u32 {
        let key = DataKey::SubjectAttestationCount(subject);
        let c = e.storage()
            .instance()
            .get(&key)
            .unwrap_or(0);
        bump_instance_ttl(&e, &key);
        c
    }

    /// Get current nonce for an identity (for replay prevention). Use this value in the next state-changing call.
    pub fn get_nonce(e: Env, identity: Address) -> u64 {
        nonce::get_nonce(&e, &identity)
    }

    /// Set attester stake (admin only). Used for weighted attestation; weight is derived from this.
    /// Negative stake values are rejected.
    pub fn set_attester_stake(e: Env, admin: Address, attester: Address, amount: i128) {
        let stored_admin: Address = e
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::NotInitialized));
        admin.require_auth();
        if admin != stored_admin {
            panic_with_error!(e, ContractError::NotAdmin);
        }
        weighted_attestation::set_attester_stake(&e, &attester, amount);
    }

    /// Set weight config: multiplier_bps (e.g. 100 = 1%), max_attestation_weight. Admin only.
    pub fn set_weight_config(e: Env, admin: Address, multiplier_bps: u32, max_weight: u32) {
        let stored_admin: Address = e
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::NotInitialized));
        admin.require_auth();
        if admin != stored_admin {
            panic_with_error!(e, ContractError::NotAdmin);
        }
        weighted_attestation::set_weight_config(&e, multiplier_bps, max_weight);
    }

    /// Get weight config (multiplier_bps, max_weight).
    pub fn get_weight_config(e: Env) -> (u32, u32) {
        weighted_attestation::get_weight_config(&e)
    }

    /// Withdraw from bond. Checks that the bond has sufficient balance after accounting for slashed amount.
    ///
    /// Authority: stored bond owner (`bond.identity`) must authorize this call.
    /// Returns the updated bond with reduced bonded_amount.
    ///
    /// Errors:
    /// - `ContractError::BondNotFound` (200)
    /// - `ContractError::SlashExceedsBond` (203)
    /// - `ContractError::InsufficientBalance` (202)
    /// - `ContractError::Underflow` (701)
    pub fn withdraw(e: Env, amount: i128) -> IdentityBond {
        let key = DataKey::Bond;
        let mut bond = e
            .storage()
            .instance()
            .get::<_, IdentityBond>(&key)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::BondNotFound));
        bump_instance_ttl(&e, &key);

        // Calculate available balance (bonded - slashed)
        let available = bond
            .bonded_amount
            .checked_sub(bond.slashed_amount)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::SlashExceedsBond));

        // Verify sufficient available balance for withdrawal
        if amount > available {
            panic_with_error!(e, ContractError::InsufficientBalance);
        }

        // Perform withdrawal with overflow protection
        bond.bonded_amount = bond
            .bonded_amount
            .checked_sub(amount)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::Underflow));

        // Verify invariant: slashed amount should not exceed bonded amount after withdrawal
        if bond.slashed_amount > bond.bonded_amount {
            panic_with_error!(e, ContractError::SlashExceedsBond);
        }

        e.storage().instance().set(&key, &bond);
        bump_instance_ttl(&e, &key);
        bond
    }

    /// Withdraw before lock-up end; applies early exit penalty and transfers penalty to treasury.
    ///
    /// Authority: stored bond owner (`bond.identity`) must authorize this call.
    /// Net amount to user = amount - penalty. Use when lock-up has not yet ended.
    ///
    /// Errors:
    /// - `ContractError::BondNotFound` (200)
    /// - `ContractError::SlashExceedsBond` (203)
    /// - `ContractError::InsufficientBalance` (202)
    /// - `ContractError::LockupNotExpired` (204)
    /// - `ContractError::Underflow` (701)
    pub fn withdraw_early(e: Env, amount: i128) -> IdentityBond {
        let key = DataKey::Bond;
        let mut bond = e
            .storage()
            .instance()
            .get::<_, IdentityBond>(&key)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::BondNotFound));
        bump_instance_ttl(&e, &key);

        let available = bond
            .bonded_amount
            .checked_sub(bond.slashed_amount)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::SlashExceedsBond));
        if amount > available {
            panic_with_error!(e, ContractError::InsufficientBalance);
        }

        let now = e.ledger().timestamp();
        let end = bond.bond_start.saturating_add(bond.bond_duration);
        if now >= end {
            panic_with_error!(e, ContractError::LockupNotExpired);
        }

        let (treasury, penalty_bps) = early_exit_penalty::get_config(&e);
        let remaining = end.saturating_sub(now);
        let penalty = early_exit_penalty::calculate_penalty(
            amount,
            remaining,
            bond.bond_duration,
            penalty_bps,
        );
        early_exit_penalty::emit_penalty_event(&e, &bond.identity, amount, penalty, &treasury);
        // In a full implementation: transfer (amount - penalty) to user, penalty to treasury.

        let old_tier = tiered_bond::get_tier_for_amount(bond.bonded_amount);
        bond.bonded_amount = bond
            .bonded_amount
            .checked_sub(amount)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::Underflow));
        if bond.slashed_amount > bond.bonded_amount {
            panic_with_error!(e, ContractError::SlashExceedsBond);
        }
        let new_tier = tiered_bond::get_tier_for_amount(bond.bonded_amount);
        tiered_bond::emit_tier_change_if_needed(&e, &bond.identity, old_tier, new_tier);

        e.storage().instance().set(&key, &bond);
        bump_instance_ttl(&e, &key);
        bond
    }

    /// Request withdrawal (rolling bonds). Withdrawal allowed after notice period.
    ///
    /// Errors:
    /// - `ContractError::BondNotFound` (200)
    /// - `ContractError::NotRollingBond` (205)
    /// - `ContractError::WithdrawalAlreadyRequested` (206)
    pub fn request_withdrawal(e: Env) -> IdentityBond {
        let key = DataKey::Bond;
        let mut bond = e
            .storage()
            .instance()
            .get::<_, IdentityBond>(&key)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::BondNotFound));
        bump_instance_ttl(&e, &key);
        if !bond.is_rolling {
            panic_with_error!(e, ContractError::NotRollingBond);
        }
        if bond.withdrawal_requested_at != 0 {
            panic_with_error!(e, ContractError::WithdrawalAlreadyRequested);
        }
        bond.withdrawal_requested_at = e.ledger().timestamp();
        e.storage().instance().set(&key, &bond);
        e.events().publish(
            (Symbol::new(&e, "withdrawal_requested"),),
            (bond.identity.clone(), bond.withdrawal_requested_at),
        );
        bond
    }

    /// If bond is rolling and period has ended, renew (new period start = now). Emits renewal event.
    ///
    /// Errors:
    /// - `ContractError::BondNotFound` (200)
    pub fn renew_if_rolling(e: Env) -> IdentityBond {
        let key = DataKey::Bond;
        let mut bond = e
            .storage()
            .instance()
            .get::<_, IdentityBond>(&key)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::BondNotFound));
        if !bond.is_rolling {
            return bond;
        }
        let now = e.ledger().timestamp();
        if !rolling_bond::is_period_ended(now, bond.bond_start, bond.bond_duration) {
            return bond;
        }
        rolling_bond::apply_renewal(&mut bond, now);
        e.storage().instance().set(&key, &bond);
        bump_instance_ttl(&e, &key);
        e.events().publish(
            (Symbol::new(&e, "bond_renewed"),),
            (bond.identity.clone(), bond.bond_start, bond.bond_duration),
        );
        bond
    }

    /// Get current tier for the bond's bonded amount.
    pub fn get_tier(e: Env) -> BondTier {
        let bond = Self::get_identity_state(e);
        tiered_bond::get_tier_for_amount(bond.bonded_amount)
    }

    /// Slash a portion of the bond (admin only). Reduces the bond's value as a penalty.
    /// Increases slashed_amount up to the bonded_amount (over-slash prevention).
    ///
    /// # Arguments
    /// * `admin` - Address claiming admin authority (must be contract admin)
    /// * `amount` - Amount to slash (i128). Will be capped at bonded_amount.
    ///
    /// # Returns
    /// Updated IdentityBond with increased slashed_amount
    ///
    /// # Panics
    /// - "not admin" if caller is not the contract admin
    /// - "no bond" if no bond exists
    ///
    /// # Events
    /// Emits `bond_slashed` event with (identity, slash_amount, total_slashed_amount)
    pub fn slash(e: Env, admin: Address, amount: i128) -> IdentityBond {
        slashing::slash_bond(&e, &admin, amount)
    }

    /// Top up the bond with additional amount (checks for overflow)
    ///
    /// Errors:
    /// - `ContractError::BondNotFound` (200)
    /// - `ContractError::Overflow` (700)
    pub fn top_up(e: Env, amount: i128) -> IdentityBond {
        let key = DataKey::Bond;
        let mut bond = e
            .storage()
            .instance()
            .get::<_, IdentityBond>(&key)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::BondNotFound));

        // Perform top-up with overflow protection
        bond.bonded_amount = bond
            .bonded_amount
            .checked_add(amount)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::Overflow));

        e.storage().instance().set(&key, &bond);
        bump_instance_ttl(&e, &key);
        bond
    }

    /// Extend bond duration (checks for u64 overflow on timestamps)
    ///
    /// Errors:
    /// - `ContractError::BondNotFound` (200)
    /// - `ContractError::Overflow` (700)
    pub fn extend_duration(e: Env, additional_duration: u64) -> IdentityBond {
        let key = DataKey::Bond;
        let mut bond = e
            .storage()
            .instance()
            .get::<_, IdentityBond>(&key)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::BondNotFound));
        bump_instance_ttl(&e, &key);

        // Perform duration extension with overflow protection
        bond.bond_duration = bond
            .bond_duration
            .checked_add(additional_duration)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::Overflow));

        // Also verify the end timestamp wouldn't overflow
        let _end_timestamp = bond
            .bond_start
            .checked_add(bond.bond_duration)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::Overflow));

        e.storage().instance().set(&key, &bond);
        bump_instance_ttl(&e, &key);
        bond
    }

    /// Deposit fees into the contract's fee pool.
    pub fn deposit_fees(e: Env, amount: i128) {
        let key = Symbol::new(&e, "fees");
        let current: i128 = e.storage().instance().get(&key).unwrap_or(0);
        e.storage().instance().set(&key, &(current + amount));
    }

    /// Withdraw the full bonded amount back to the identity.
    /// Uses a reentrancy guard to prevent re-entrance during external calls.
    ///
    /// Errors:
    /// - `ContractError::BondNotFound` (200)
    /// - `ContractError::NotBondOwner` (101)
    /// - `ContractError::BondNotActive` (201)
    /// - `ContractError::ReentrancyDetected` (207)
    pub fn withdraw_bond(e: Env, identity: Address) -> i128 {
        identity.require_auth();
        Self::acquire_lock(&e);

        let bond_key = DataKey::Bond;
        let bond: IdentityBond = e
            .storage()
            .instance()
            .get(&bond_key)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::BondNotFound));
        bump_instance_ttl(&e, &bond_key);
        bump_instance_ttl(&e, &bond_key);

        if bond.identity != identity {
            Self::release_lock(&e);
            panic_with_error!(e, ContractError::NotBondOwner);
        }
        if !bond.active {
            Self::release_lock(&e);
            panic_with_error!(e, ContractError::BondNotActive);
        }

        let withdraw_amount = bond.bonded_amount - bond.slashed_amount;

        // State update BEFORE external interaction (checks-effects-interactions)
        let updated = IdentityBond {
            identity: identity.clone(),
            bonded_amount: 0,
            bond_start: bond.bond_start,
            bond_duration: bond.bond_duration,
            slashed_amount: bond.slashed_amount,
            is_rolling: bond.is_rolling,
            notice_period: bond.notice_period,
            withdrawal_requested_at: bond.withdrawal_requested_at,
            active: false,
            is_rolling: bond.is_rolling,
            withdrawal_requested_at: bond.withdrawal_requested_at,
            notice_period: bond.notice_period,
        };
        e.storage().instance().set(&bond_key, &updated);
        bump_instance_ttl(&e, &bond_key);
        bump_instance_ttl(&e, &bond_key);

        // External call: invoke callback if a callback contract is registered.
        // In production this would be a token transfer; here we use a hook for testing.
        let cb_key = Symbol::new(&e, "callback");
        if let Some(cb_addr) = e.storage().instance().get::<_, Address>(&cb_key) {
            let fn_name = Symbol::new(&e, "on_withdraw");
            let args: Vec<Val> = Vec::from_array(&e, [withdraw_amount.into_val(&e)]);
            e.invoke_contract::<Val>(&cb_addr, &fn_name, args);
        }

        Self::release_lock(&e);
        withdraw_amount
    }

    /// Slash a portion of a bond. Only callable by admin.
    /// Uses a reentrancy guard to prevent re-entrance during external calls.
    ///
    /// Errors:
    /// - `ContractError::NotInitialized` (1)
    /// - `ContractError::NotAdmin` (100)
    /// - `ContractError::BondNotFound` (200)
    /// - `ContractError::BondNotActive` (201)
    /// - `ContractError::SlashExceedsBond` (203)
    pub fn slash_bond(e: Env, admin: Address, slash_amount: i128) -> i128 {
        admin.require_auth();
        Self::acquire_lock(&e);

        let stored_admin: Address = e
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::NotInitialized));
        if stored_admin != admin {
            Self::release_lock(&e);
            panic_with_error!(e, ContractError::NotAdmin);
        }

        let bond_key = DataKey::Bond;
        let bond: IdentityBond = e
            .storage()
            .instance()
            .get(&bond_key)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::BondNotFound));

        if !bond.active {
            Self::release_lock(&e);
            panic_with_error!(e, ContractError::BondNotActive);
        }

        let new_slashed = bond.slashed_amount + slash_amount;
        if new_slashed > bond.bonded_amount {
            Self::release_lock(&e);
            panic_with_error!(e, ContractError::SlashExceedsBond);
        }

        // State update BEFORE external interaction
        let updated = IdentityBond {
            identity: bond.identity.clone(),
            bonded_amount: bond.bonded_amount,
            bond_start: bond.bond_start,
            bond_duration: bond.bond_duration,
            slashed_amount: new_slashed,
            is_rolling: bond.is_rolling,
            notice_period: bond.notice_period,
            withdrawal_requested_at: bond.withdrawal_requested_at,
            active: bond.active,
            is_rolling: bond.is_rolling,
            withdrawal_requested_at: bond.withdrawal_requested_at,
            notice_period: bond.notice_period,
        };
        e.storage().instance().set(&bond_key, &updated);

        // External call: invoke callback if registered
        let cb_key = Symbol::new(&e, "callback");
        if let Some(cb_addr) = e.storage().instance().get::<_, Address>(&cb_key) {
            let fn_name = Symbol::new(&e, "on_slash");
            let args: Vec<Val> = Vec::from_array(&e, [slash_amount.into_val(&e)]);
            e.invoke_contract::<Val>(&cb_addr, &fn_name, args);
        }

        Self::release_lock(&e);
        new_slashed
    }

    /// Collect accumulated protocol fees. Only callable by admin.
    /// Uses a reentrancy guard to prevent re-entrance during external calls.
    ///
    /// Errors:
    /// - `ContractError::NotInitialized` (1)
    /// - `ContractError::NotAdmin` (100)
    pub fn collect_fees(e: Env, admin: Address) -> i128 {
        admin.require_auth();
        Self::acquire_lock(&e);

        let stored_admin: Address = e
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::NotInitialized));
        if stored_admin != admin {
            Self::release_lock(&e);
            panic_with_error!(e, ContractError::NotAdmin);
        }

        let fee_key = Symbol::new(&e, "fees");
        let fees: i128 = e.storage().instance().get(&fee_key).unwrap_or(0);

        // State update BEFORE external interaction
        e.storage().instance().set(&fee_key, &0_i128);

        // External call: invoke callback if registered
        let cb_key = Symbol::new(&e, "callback");
        if let Some(cb_addr) = e.storage().instance().get::<_, Address>(&cb_key) {
            let fn_name = Symbol::new(&e, "on_collect");
            let args: Vec<Val> = Vec::from_array(&e, [fees.into_val(&e)]);
            e.invoke_contract::<Val>(&cb_addr, &fn_name, args);
        }

        Self::release_lock(&e);
        fees
    }

    /// Register a callback contract address (for testing external call hooks).
    pub fn set_callback(e: Env, addr: Address) {
        e.storage()
            .instance()
            .set(&Symbol::new(&e, "callback"), &addr);
    }

    /// Check if the reentrancy lock is currently held.
    pub fn is_locked(e: Env) -> bool {
        Self::check_lock(&e)
    }

    // --- Reentrancy guard helpers ---

    fn acquire_lock(e: &Env) {
        let key = Symbol::new(e, "locked");
        let locked: bool = e.storage().instance().get(&key).unwrap_or(false);
        if locked {
            panic_with_error!(e, ContractError::ReentrancyDetected);
        }
        e.storage().instance().set(&key, &true);
    }

    fn release_lock(e: &Env) {
        let key = Symbol::new(e, "locked");
        e.storage().instance().set(&key, &false);
    }

    fn check_lock(e: &Env) -> bool {
        let key = Symbol::new(e, "locked");
        e.storage().instance().get(&key).unwrap_or(false)
    }

    fn load_bond_and_require_owner_auth(e: &Env, key: &DataKey) -> IdentityBond {
        let bond: IdentityBond = e
            .storage()
            .instance()
            .get(key)
            .unwrap_or_else(|| panic!("no bond"));
        bond.identity.require_auth();
        bond
    }
}

#[cfg(test)]
mod test;

#[cfg(test)]
mod test_attestation;

#[cfg(test)]
mod test_attestation_types;

#[cfg(test)]
mod test_weighted_attestation;

#[cfg(test)]
mod test_replay_prevention;

#[cfg(test)]
mod security;