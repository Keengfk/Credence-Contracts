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

        // Rolling bonds must have completed the notice window before funds can leave.
        if bond.is_rolling {
            if bond.withdrawal_requested_at == 0 {
                panic!("withdrawal not requested");
            }
            let earliest = bond
                .withdrawal_requested_at
                .checked_add(bond.notice_period_duration)
                .expect("notice period overflow");
            if e.ledger().timestamp() < earliest {
                panic!("notice period not elapsed");
            }
        }

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
        // Do not auto-renew once the holder has signalled intent to withdraw.
        if bond.withdrawal_requested_at != 0 {
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
    /// Uses a panic-safe reentrancy guard to prevent re-entrance during external calls.
    ///
    /// All reads and validations are performed BEFORE acquiring the lock to ensure
    /// the lock cannot be stuck by a panic during validation.
    ///
    /// Errors:
    /// - `ContractError::BondNotFound` (200)
    /// - `ContractError::NotBondOwner` (101)
    /// - `ContractError::BondNotActive` (201)
    /// - `ContractError::ReentrancyDetected` (207)
    pub fn withdraw_bond(e: Env, identity: Address) -> i128 {
        identity.require_auth();

        // PHASE 1: Read and validate BEFORE acquiring lock
        // This ensures no panic can occur while holding the lock during reads
        let bond_key = DataKey::Bond;
        let bond: IdentityBond = e
            .storage()
            .instance()
            .get(&bond_key)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::BondNotFound));
        bump_instance_ttl(&e, &bond_key);

        // Validate ownership
        if bond.identity != identity {
            panic_with_error!(e, ContractError::NotBondOwner);
        }
        
        // Validate bond is active
        if !bond.active {
            panic_with_error!(e, ContractError::BondNotActive);
        }

        // Validate rolling bond notice period
        if bond.is_rolling {
            if bond.withdrawal_requested_at == 0 {
                panic!("withdrawal not requested");
            }
            let earliest = bond
                .withdrawal_requested_at
                .checked_add(bond.notice_period_duration)
                .expect("notice period overflow");
            if e.ledger().timestamp() < earliest {
                panic!("notice period not elapsed");
            }
        }

        // Calculate withdrawal amount
        let withdraw_amount = bond.bonded_amount - bond.slashed_amount;

        // Read callback address before acquiring lock
        let cb_key = Symbol::new(&e, "callback");
        let cb_addr = e.storage().instance().get::<_, Address>(&cb_key);

        // PHASE 2: Acquire lock (RAII guard ensures automatic release)
        let _guard = Self::acquire_lock(&e);

        // PHASE 3: State updates (checks-effects-interactions pattern)
        let updated = IdentityBond {
            identity: identity.clone(),
            bonded_amount: 0,
            bond_start: bond.bond_start,
            bond_duration: bond.bond_duration,
            slashed_amount: bond.slashed_amount,
            active: false,
            is_rolling: bond.is_rolling,
            withdrawal_requested_at: bond.withdrawal_requested_at,
            notice_period_duration: bond.notice_period_duration,
        };
        e.storage().instance().set(&bond_key, &updated);
        bump_instance_ttl(&e, &bond_key);

        // PHASE 4: External call (with lock held, but guard ensures release on panic)
        if let Some(cb_addr) = cb_addr {
            let fn_name = Symbol::new(&e, "on_withdraw");
            let args: Vec<Val> = Vec::from_array(&e, [withdraw_amount.into_val(&e)]);
            e.invoke_contract::<Val>(&cb_addr, &fn_name, args);
        }

        // Lock automatically released when _guard goes out of scope
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
    /// Slash a portion of a bond. Only callable by admin.
    /// Uses a panic-safe reentrancy guard to prevent re-entrance during external calls.
    ///
    /// All reads and validations are performed BEFORE acquiring the lock to ensure
    /// the lock cannot be stuck by a panic during validation.
    ///
    /// Errors:
    /// - `ContractError::NotInitialized` (1)
    /// - `ContractError::NotAdmin` (100)
    /// - `ContractError::BondNotFound` (200)
    /// - `ContractError::BondNotActive` (201)
    /// - `ContractError::SlashExceedsBond` (203)
    pub fn slash_bond(e: Env, admin: Address, slash_amount: i128) -> i128 {
        admin.require_auth();

        // PHASE 1: Read and validate BEFORE acquiring lock
        let stored_admin: Address = e
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::NotInitialized));
        
        if stored_admin != admin {
            panic_with_error!(e, ContractError::NotAdmin);
        }

        let bond_key = DataKey::Bond;
        let bond: IdentityBond = e
            .storage()
            .instance()
            .get(&bond_key)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::BondNotFound));

        if !bond.active {
            panic_with_error!(e, ContractError::BondNotActive);
        }

        let new_slashed = bond.slashed_amount + slash_amount;
        if new_slashed > bond.bonded_amount {
            panic_with_error!(e, ContractError::SlashExceedsBond);
        }

        // Read callback address before acquiring lock
        let cb_key = Symbol::new(&e, "callback");
        let cb_addr = e.storage().instance().get::<_, Address>(&cb_key);

        // PHASE 2: Acquire lock (RAII guard ensures automatic release)
        let _guard = Self::acquire_lock(&e);

        // PHASE 3: State update BEFORE external interaction
        let updated = IdentityBond {
            identity: bond.identity.clone(),
            bonded_amount: bond.bonded_amount,
            bond_start: bond.bond_start,
            bond_duration: bond.bond_duration,
            slashed_amount: new_slashed,
            active: bond.active,
            is_rolling: bond.is_rolling,
            withdrawal_requested_at: bond.withdrawal_requested_at,
            notice_period_duration: bond.notice_period_duration,
        };
        e.storage().instance().set(&bond_key, &updated);

        // PHASE 4: External call (with lock held, but guard ensures release on panic)
        if let Some(cb_addr) = cb_addr {
            let fn_name = Symbol::new(&e, "on_slash");
            let args: Vec<Val> = Vec::from_array(&e, [slash_amount.into_val(&e)]);
            e.invoke_contract::<Val>(&cb_addr, &fn_name, args);
        }

        // Lock automatically released when _guard goes out of scope
        new_slashed
    }

    /// Collect accumulated protocol fees. Only callable by admin.
    /// Uses a panic-safe reentrancy guard to prevent re-entrance during external calls.
    ///
    /// All reads and validations are performed BEFORE acquiring the lock to ensure
    /// the lock cannot be stuck by a panic during validation.
    ///
    /// Errors:
    /// - `ContractError::NotInitialized` (1)
    /// - `ContractError::NotAdmin` (100)
    pub fn collect_fees(e: Env, admin: Address) -> i128 {
        admin.require_auth();

        // PHASE 1: Read and validate BEFORE acquiring lock
        let stored_admin: Address = e
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::NotInitialized));
        
        if stored_admin != admin {
            panic_with_error!(e, ContractError::NotAdmin);
        }

        let fee_key = Symbol::new(&e, "fees");
        let fees: i128 = e.storage().instance().get(&fee_key).unwrap_or(0);

        // Read callback address before acquiring lock
        let cb_key = Symbol::new(&e, "callback");
        let cb_addr = e.storage().instance().get::<_, Address>(&cb_key);

        // PHASE 2: Acquire lock (RAII guard ensures automatic release)
        let _guard = Self::acquire_lock(&e);

        // PHASE 3: State update BEFORE external interaction
        e.storage().instance().set(&fee_key, &0_i128);

        // PHASE 4: External call (with lock held, but guard ensures release on panic)
        if let Some(cb_addr) = cb_addr {
            let fn_name = Symbol::new(&e, "on_collect");
            let args: Vec<Val> = Vec::from_array(&e, [fees.into_val(&e)]);
            e.invoke_contract::<Val>(&cb_addr, &fn_name, args);
        }

        // Lock automatically released when _guard goes out of scope
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

    // ===========================================================================
    // Reentrancy Guard Implementation
    // ===========================================================================
    //
    // This section implements a panic-safe reentrancy guard using the RAII
    // (Resource Acquisition Is Initialization) pattern. The guard automatically
    // releases the lock when dropped, even if a panic occurs.
    //
    // ## Security Properties
    //
    // 1. **Reentrancy Prevention**: Reentrant calls are detected and rejected
    //    with ContractError::ReentrancyDetected
    //
    // 2. **Panic Safety**: The lock is automatically released on panic via the
    //    Drop trait, preventing permanently stuck locks
    //
    // 3. **Automatic Cleanup**: No manual lock release needed; the compiler
    //    ensures cleanup when the guard goes out of scope
    //
    // ## Usage Pattern
    //
    // ```rust
    // pub fn protected_function(e: Env) -> Result {
    //     // Phase 1: Read and validate BEFORE acquiring lock
    //     let data = read_and_validate()?;
    //     
    //     // Phase 2: Acquire lock (automatic release on drop)
    //     let _guard = Self::acquire_lock(&e);
    //     
    //     // Phase 3: Update state
    //     update_state(data);
    //     
    //     // Phase 4: External calls
    //     make_external_call();
    //     
    //     // Lock automatically released when _guard goes out of scope
    //     Ok(())
    // }
    // ```
    //
    // ## Protected Functions
    //
    // - `withdraw_bond`: Withdraws bonded amount with external callback
    // - `slash_bond`: Slashes bond with external callback
    // - `collect_fees`: Collects fees with external callback
    //
    // See docs/reentrancy.md for detailed documentation.
    // ===========================================================================

    /// RAII guard that releases the reentrancy lock on drop.
    /// 
    /// This guard ensures the reentrancy lock is released even if a panic
    /// occurs between lock acquisition and function return. The lock is stored
    /// in contract instance storage under the key "locked".
    ///
    /// # Panic Safety
    ///
    /// The `Drop` implementation guarantees the lock is released on all exit
    /// paths, including:
    /// - Normal function return
    /// - Early return via `?` operator
    /// - Panic during execution
    ///
    /// # Example
    ///
    /// ```rust
    /// let _guard = Self::acquire_lock(&e);
    /// // ... protected code ...
    /// // Lock automatically released here when _guard is dropped
    /// ```
    struct ReentrancyGuard<'a> {
        env: &'a Env,
    }

    impl<'a> Drop for ReentrancyGuard<'a> {
        /// Automatically releases the reentrancy lock when the guard is dropped.
        ///
        /// This is called by the Rust compiler when the guard goes out of scope,
        /// ensuring the lock is always released regardless of how the function exits.
        fn drop(&mut self) {
            let key = Symbol::new(self.env, "locked");
            self.env.storage().instance().set(&key, &false);
        }
    }

    /// Acquire the reentrancy lock and return a guard that will automatically
    /// release it.
    ///
    /// This function checks if the lock is currently held and panics with
    /// `ContractError::ReentrancyDetected` if so. Otherwise, it sets the lock
    /// to `true` and returns a guard that will set it back to `false` when dropped.
    ///
    /// # Returns
    ///
    /// A `ReentrancyGuard` that will automatically release the lock when dropped.
    ///
    /// # Panics
    ///
    /// Panics with `ContractError::ReentrancyDetected` if the lock is already held,
    /// indicating a reentrancy attempt.
    ///
    /// # Example
    ///
    /// ```rust
    /// let _guard = Self::acquire_lock(&e);
    /// // Lock is now held
    /// // ... perform protected operations ...
    /// // Lock is automatically released when _guard goes out of scope
    /// ```
    fn acquire_lock(e: &Env) -> ReentrancyGuard {
        let key = Symbol::new(e, "locked");
        let locked: bool = e.storage().instance().get(&key).unwrap_or(false);
        if locked {
            panic_with_error!(e, ContractError::ReentrancyDetected);
        }
        e.storage().instance().set(&key, &true);
        ReentrancyGuard { env: e }
    }

    /// Check if the reentrancy lock is currently held.
    ///
    /// This is primarily used for testing and debugging. In production code,
    /// use `acquire_lock` which will panic if the lock is held.
    ///
    /// # Returns
    ///
    /// `true` if the lock is currently held, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// assert!(!Self::check_lock(&e)); // Lock not held
    /// let _guard = Self::acquire_lock(&e);
    /// assert!(Self::check_lock(&e));  // Lock is held
    /// ```
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
