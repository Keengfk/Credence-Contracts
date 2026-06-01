use crate::{IdentityBond, DataKey, BondTier, Attestation};
use crate::types::AttestationDedupKey;
use crate::{early_exit_penalty, nonce, rolling_bond, slashing, tiered_bond, weighted_attestation};

use credence_errors::ContractError;
use soroban_sdk::{
    contract, contractimpl, contracttype, panic_with_error, Address, Env, String, Symbol,
    Val, Vec,
};

// Re-export attestation type (definitions and validation in types::attestation).
pub use crate::Attestation;

// Storage TTL policy constants.
const STORAGE_TTL_EXTEND_TO: u64 = 31_536_000;

/// Source-level storage budget for a hot path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HotPathStorageBudget {
    pub bond_reads: u32,
    pub bond_writes: u32,
    pub admin_reads: u32,
    pub callback_reads: u32,
    pub lock_reads: u32,
    pub lock_writes: u32,
    pub config_reads: u32,
}

pub const WITHDRAW_EARLY_STORAGE_BUDGET: HotPathStorageBudget = HotPathStorageBudget {
    bond_reads: 1,
    bond_writes: 1,
    admin_reads: 0,
    callback_reads: 0,
    lock_reads: 0,
    lock_writes: 0,
    config_reads: 1,
};

pub const WITHDRAW_BOND_STORAGE_BUDGET: HotPathStorageBudget = HotPathStorageBudget {
    bond_reads: 1,
    bond_writes: 1,
    admin_reads: 0,
    callback_reads: 1,
    lock_reads: 1,
    lock_writes: 2,
    config_reads: 0,
};

pub const SLASH_BOND_STORAGE_BUDGET: HotPathStorageBudget = HotPathStorageBudget {
    bond_reads: 1,
    bond_writes: 1,
    admin_reads: 1,
    callback_reads: 1,
    lock_reads: 1,
    lock_writes: 2,
    config_reads: 0,
};

fn bump_instance_ttl(e: &Env) {
    e.storage()
        .instance()
        .extend_ttl(STORAGE_TTL_EXTEND_TO / 2, STORAGE_TTL_EXTEND_TO);
}

#[contract]
pub struct CredenceBond;

#[contractimpl]
impl CredenceBond {
    pub fn initialize(e: Env, admin: Address) {
        admin.require_auth();
        e.storage().instance().set(&DataKey::Admin, &admin);
    }

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

    pub fn is_attester(e: Env, attester: Address) -> bool {
        e.storage()
            .instance()
            .get(&DataKey::Attester(attester))
            .unwrap_or(false)
    }

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
        if e.storage().instance().has(&key) {
            panic_with_error!(e, ContractError::BondAlreadyExists);
        }
        e.storage().instance().set(&key, &bond);
        bump_instance_ttl(&e);
        let tier = tiered_bond::get_tier_for_amount(amount);
        tiered_bond::emit_tier_change_if_needed(&e, &identity, BondTier::Bronze, tier);
        e.events().publish(
            (Symbol::new(&e, "bond_created"),),
            (identity.clone(), amount, bond_start, duration),
        );
        bond
    }

    pub fn get_identity_state(e: Env) -> IdentityBond {
        let key = DataKey::Bond;
        let bond = e
            .storage()
            .instance()
            .get::<_, IdentityBond>(&key)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::BondNotFound));
        bump_instance_ttl(&e);
        bond
    }

    pub fn add_attestation(
        e: Env,
        attester: Address,
        subject: Address,
        attestation_data: String,
        nonce_val: u64,
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
        nonce::consume_nonce(&e, &attester, nonce_val);

        let dedup_key = AttestationDedupKey {
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
        Attestation::validate_weight(weight);

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
        bump_instance_ttl(&e);
        e.storage().instance().set(&dedup_key, &id);
        bump_instance_ttl(&e);

        let subject_key = DataKey::SubjectAttestations(subject.clone());
        let mut attestations: Vec<u64> = e
            .storage()
            .instance()
            .get(&subject_key)
            .unwrap_or(Vec::new(&e));
        attestations.push_back(id);
        e.storage().instance().set(&subject_key, &attestations);
        bump_instance_ttl(&e);

        let count_key = DataKey::SubjectAttestationCount(subject.clone());
        let count: u32 = e.storage().instance().get(&count_key).unwrap_or(0);
        e.storage()
            .instance()
            .set(&count_key, &count.saturating_add(1));
        bump_instance_ttl(&e);

        e.events().publish(
            (Symbol::new(&e, "attestation_added"), subject),
            (id, attester, attestation_data, weight),
        );
        attestation
    }

    pub fn revoke_attestation(e: Env, attester: Address, attestation_id: u64, nonce_val: u64) {
        attester.require_auth();
        nonce::consume_nonce(&e, &attester, nonce_val);

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
        bump_instance_ttl(&e);

        let dedup_key = AttestationDedupKey {
            verifier: attestation.verifier.clone(),
            identity: attestation.identity.clone(),
            attestation_data: attestation.attestation_data.clone(),
        };
        e.storage().instance().remove(&dedup_key);

        let count_key = DataKey::SubjectAttestationCount(attestation.identity.clone());
        let count: u32 = e.storage().instance().get(&count_key).unwrap_or(0);
        e.storage()
            .instance()
            .set(&count_key, &count.saturating_sub(1));
        bump_instance_ttl(&e);

        e.events().publish(
            (
                Symbol::new(&e, "attestation_revoked"),
                attestation.identity.clone(),
            ),
            (attestation_id, attester),
        );
    }

    pub fn get_attestation(e: Env, attestation_id: u64) -> Attestation {
        let key = DataKey::Attestation(attestation_id);
        let att = e
            .storage()
            .instance()
            .get(&key)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::AttestationNotFound));
        bump_instance_ttl(&e);
        att
    }

    pub fn get_subject_attestations(e: Env, subject: Address) -> Vec<u64> {
        let key = DataKey::SubjectAttestations(subject);
        let v = e.storage().instance().get(&key).unwrap_or(Vec::new(&e));
        bump_instance_ttl(&e);
        v
    }

    pub fn get_subject_attestation_count(e: Env, subject: Address) -> u32 {
        let key = DataKey::SubjectAttestationCount(subject);
        let c = e.storage().instance().get(&key).unwrap_or(0);
        bump_instance_ttl(&e);
        c
    }

    pub fn get_nonce(e: Env, identity: Address) -> u64 {
        nonce::get_nonce(&e, &identity)
    }

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

    pub fn get_weight_config(e: Env) -> (u32, u32) {
        weighted_attestation::get_weight_config(&e)
    }

    pub fn withdraw(e: Env, identity: Address, amount: i128) -> IdentityBond {
        identity.require_auth();
        let key = DataKey::Bond;
        let mut bond = e
            .storage()
            .instance()
            .get::<_, IdentityBond>(&key)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::BondNotFound));
        bump_instance_ttl(&e);

        let now = e.ledger().timestamp();
        let end = bond
            .bond_start
            .checked_add(bond.bond_duration)
            .expect("bond end timestamp overflow");
        if now < end {
            panic!("lock-up not expired; use withdraw_early");
        }

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

        let available = bond
            .bonded_amount
            .checked_sub(bond.slashed_amount)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::SlashExceedsBond));
        if amount > available {
            panic_with_error!(e, ContractError::InsufficientBalance);
        }

        let old_amount = bond.bonded_amount;
        bond.bonded_amount = bond
            .bonded_amount
            .checked_sub(amount)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::Underflow));
        if bond.slashed_amount > bond.bonded_amount {
            panic_with_error!(e, ContractError::SlashExceedsBond);
        }

        e.storage().instance().set(&key, &bond);
        bump_instance_ttl(&e);
        e.events().publish(
            (Symbol::new(&e, "bond_withdrawn"),),
            (bond.identity.clone(), old_amount, bond.bonded_amount, now),
        );
        bond
    }

    pub fn withdraw_early(e: Env, amount: i128) -> IdentityBond {
        let key = DataKey::Bond;
        let mut bond = e
            .storage()
            .instance()
            .get::<_, IdentityBond>(&key)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::BondNotFound));
        bump_instance_ttl(&e);

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
        bump_instance_ttl(&e);
        bond
    }

    pub fn request_withdrawal(e: Env, identity: Address) -> IdentityBond {
        identity.require_auth();
        let key = DataKey::Bond;
        let mut bond = e
            .storage()
            .instance()
            .get::<_, IdentityBond>(&key)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::BondNotFound));
        bump_instance_ttl(&e);
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

    pub fn renew_if_rolling(e: Env, identity: Address) -> IdentityBond {
        let key = DataKey::Bond;
        let mut bond = e
            .storage()
            .instance()
            .get::<_, IdentityBond>(&key)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::BondNotFound));
        if !bond.is_rolling {
            return bond;
        }
        if bond.withdrawal_requested_at != 0 {
            return bond;
        }
        let now = e.ledger().timestamp();
        if !rolling_bond::is_period_ended(now, bond.bond_start, bond.bond_duration) {
            return bond;
        }
        rolling_bond::apply_renewal(&mut bond, now);
        e.storage().instance().set(&key, &bond);
        bump_instance_ttl(&e);
        e.events().publish(
            (Symbol::new(&e, "bond_renewed"),),
            (bond.identity.clone(), bond.bond_start, bond.bond_duration),
        );
        bond
    }

    pub fn get_tier(e: Env, identity: Address) -> BondTier {
        let bond = Self::get_identity_state(e);
        tiered_bond::get_tier_for_amount(bond.bonded_amount)
    }

    pub fn slash(e: Env, admin: Address, identity: Address, amount: i128) -> IdentityBond {
        slashing::slash_bond_with_identity(&e, &admin, &identity, amount)
    }

    pub fn top_up(e: Env, identity: Address, amount: i128) -> IdentityBond {
        let key = DataKey::Bond;
        let mut bond = e
            .storage()
            .instance()
            .get::<_, IdentityBond>(&key)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::BondNotFound));

        let old_amount = bond.bonded_amount;
        bond.bonded_amount = bond
            .bonded_amount
            .checked_add(amount)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::Overflow));

        let timestamp = e.ledger().timestamp();
        e.storage().instance().set(&key, &bond);
        bump_instance_ttl(&e);
        e.events().publish(
            (Symbol::new(&e, "bond_topped_up"),),
            (bond.identity.clone(), old_amount, bond.bonded_amount, timestamp),
        );
        bond
    }

    pub fn extend_duration(e: Env, identity: Address, additional_duration: u64) -> IdentityBond {
        let key = DataKey::Bond;
        let mut bond = e
            .storage()
            .instance()
            .get::<_, IdentityBond>(&key)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::BondNotFound));
        bump_instance_ttl(&e);

        let old_duration = bond.bond_duration;
        bond.bond_duration = bond
            .bond_duration
            .checked_add(additional_duration)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::Overflow));

        let _end_timestamp = bond
            .bond_start
            .checked_add(bond.bond_duration)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::Overflow));

        let timestamp = e.ledger().timestamp();
        e.storage().instance().set(&key, &bond);
        bump_instance_ttl(&e);
        e.events().publish(
            (Symbol::new(&e, "bond_duration_extended"),),
            (bond.identity.clone(), old_duration, bond.bond_duration, timestamp),
        );
        bond
    }

    pub fn deposit_fees(e: Env, amount: i128) {
        let key = Symbol::new(&e, "fees");
        let current: i128 = e.storage().instance().get(&key).unwrap_or(0);
        e.storage().instance().set(&key, &(current + amount));
    }

    pub fn withdraw_bond(e: Env, identity: Address) -> i128 {
        identity.require_auth();

        let bond_key = DataKey::Bond;
        let bond: IdentityBond = e
            .storage()
            .instance()
            .get(&bond_key)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::BondNotFound));
        bump_instance_ttl(&e);

        if bond.identity != identity {
            panic_with_error!(e, ContractError::NotBondOwner);
        }
        if !bond.active {
            panic_with_error!(e, ContractError::BondNotActive);
        }

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

        let withdraw_amount = bond.bonded_amount - bond.slashed_amount;

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
        bump_instance_ttl(&e);

        let cb_key = Symbol::new(&e, "callback");
        if let Some(cb_addr) = e.storage().instance().get::<_, Address>(&cb_key) {
            let fn_name = Symbol::new(&e, "on_withdraw");
            let args: Vec<Val> = Vec::from_array(&e, [withdraw_amount.into_val(&e)]);
            e.invoke_contract::<Val>(&cb_addr, &fn_name, args);
        }

        withdraw_amount
    }

    pub fn slash_bond(e: Env, admin: Address, slash_amount: i128) -> i128 {
        admin.require_auth();

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
        e.events().publish(
            (Symbol::new(&e, "bond_slashed"),),
            (bond.identity.clone(), slash_amount, new_slashed),
        );

        let cb_key = Symbol::new(&e, "callback");
        if let Some(cb_addr) = e.storage().instance().get::<_, Address>(&cb_key) {
            let fn_name = Symbol::new(&e, "on_slash");
            let args: Vec<Val> = Vec::from_array(&e, [slash_amount.into_val(&e)]);
            e.invoke_contract::<Val>(&cb_addr, &fn_name, args);
        }

        new_slashed
    }

    pub fn collect_fees(e: Env, admin: Address) -> i128 {
        admin.require_auth();

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
        e.storage().instance().set(&fee_key, &0_i128);

        let cb_key = Symbol::new(&e, "callback");
        if let Some(cb_addr) = e.storage().instance().get::<_, Address>(&cb_key) {
            let fn_name = Symbol::new(&e, "on_collect");
            let args: Vec<Val> = Vec::from_array(&e, [fees.into_val(&e)]);
            e.invoke_contract::<Val>(&cb_addr, &fn_name, args);
        }

        fees
    }

    pub fn set_callback(e: Env, addr: Address) {
        e.storage()
            .instance()
            .set(&Symbol::new(&e, "callback"), &addr);
    }

    pub fn is_locked(e: Env) -> bool {
        let key = Symbol::new(&e, "locked");
        e.storage().instance().get(&key).unwrap_or(false)
    }
}
