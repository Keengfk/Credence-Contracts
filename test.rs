#![cfg(test)]

use super::*;
use credence_errors::ContractError;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env};
use soroban_sdk::testutils::Ledger;
use soroban_sdk::testutils::LedgerInfo;
use soroban_sdk::String;

fn setup() -> (Env, Address, CredenceBondClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let contract_id = env.register(CredenceBond, ());
    let client = CredenceBondClient::new(&env, &contract_id);
    (env, admin, client)
}

fn advance_with_max_ttl(e: &Env, secs: u64, max_entry_ttl: u64) {
    e.ledger().set(LedgerInfo {
        timestamp: e.ledger().timestamp() + secs,
        protocol_version: 22,
        sequence_number: 1,
        network_id: [0; 32],
        base_reserve: 10,
        min_temp_entry_ttl: 16,
        min_persistent_entry_ttl: 16,
        max_entry_ttl,
    });
}

#[test]
fn test_ttl_bumps_on_reads_keep_entry_alive() {
    let (env, admin, client) = setup();
    env.mock_all_auths();

    // Ensure ledger allows our desired extend-to value
    advance_with_max_ttl(&env, 0, STORAGE_TTL_EXTEND_TO);

    let owner = Address::generate(&env);
    // Create a bond (create_bond calls bump TTL on write)
    let _bond = client.create_bond(&owner, &100_i128, &1000_u64);

    // Advance to just below the TTL threshold and read to bump again
    advance_with_max_ttl(&env, STORAGE_TTL_EXTEND_TO - 1, STORAGE_TTL_EXTEND_TO);
    let _ = client.get_identity_state();

    // Advance again close to the TTL and ensure read still succeeds
    advance_with_max_ttl(&env, STORAGE_TTL_EXTEND_TO - 1, STORAGE_TTL_EXTEND_TO);
    let _ = client.get_identity_state();
}

#[test]
fn test_bond_locked_for_max_duration_never_expires_before_unlock() {
    let (env, _admin, client) = setup();
    env.mock_all_auths();

    // Ensure ledger allows our desired extend-to value
    advance_with_max_ttl(&env, 0, STORAGE_TTL_EXTEND_TO);

    let owner = Address::generate(&env);
    let amount: i128 = 1000;
    // Use maximum bond duration (365 days)
    let max_duration: u64 = 31_536_000;
    let _bond = client.create_bond(&owner, &amount, &max_duration);

    // Advance to bond end (just before unlock) and ensure bond still present
    advance_with_max_ttl(&env, max_duration - 1, STORAGE_TTL_EXTEND_TO);
    let _ = client.get_identity_state();

    // Advance to unlock time and attempt withdraw_bond (owner must be able to withdraw)
    advance_with_max_ttl(&env, 2, STORAGE_TTL_EXTEND_TO);
    let withdrawn = client.withdraw_bond(&owner);
    assert_eq!(withdrawn, amount);
}

#[test]
fn test_attestation_ttl_expiry_around_threshold() {
    let (env, admin, client) = setup();
    env.mock_all_auths();

    // Use a small ledger max TTL so create-time extend will be clamped and expiry can occur.
    let ledger_ttl: u64 = 1000;
    advance_with_max_ttl(&env, 0, ledger_ttl);

    client.initialize(&admin);
    let attester = Address::generate(&env);
    client.register_attester(&attester);
    let subject = Address::generate(&env);
    let data = String::from_str(&env, "payload");

    // Nonce starts at 0
    let nonce: u64 = client.get_nonce(&attester);
    let att = client.add_attestation(&attester, &subject, &data, &nonce);

    // Read just below the ledger TTL expiry
    advance_with_max_ttl(&env, ledger_ttl - 1, ledger_ttl);
    let _ = client.get_attestation(&att.id);

    // Advance past the ledger TTL; since extend was clamped, entry should be expired
    advance_with_max_ttl(&env, 2, ledger_ttl);
    let err = client.try_get_attestation(&att.id).unwrap_err().unwrap();
    assert_eq!(err, ContractError::AttestationNotFound);
}

#[test]
fn test_not_initialized_errors() {
    let (env, _admin, client) = setup();
    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);

    let err = client
        .try_set_early_exit_config(&admin, &treasury, &500_u32)
        .unwrap_err()
        .unwrap();
    assert_eq!(err, ContractError::NotInitialized);
}

#[test]
fn test_bond_not_found_and_insufficient_balance() {
    let (env, _admin, client) = setup();

    // No bond exists yet
    let err = client.try_get_identity_state().unwrap_err().unwrap();
    assert_eq!(err, ContractError::BondNotFound);

    // Create a small bond and attempt to withdraw more than available
    let owner = Address::generate(&env);
    let _bond = client.create_bond(&owner, &100_i128, &1000_u64);
    let err2 = client.try_withdraw(&200_i128).unwrap_err().unwrap();
    assert_eq!(err2, ContractError::InsufficientBalance);
}

#[test]
fn test_request_withdrawal_not_rolling_and_already_requested() {
    let (env, _admin, client) = setup();
    let owner = Address::generate(&env);

    // Non-rolling bond -> NotRollingBond
    let _bond = client.create_bond(&owner, &100_i128, &1000_u64);
    let err = client.try_request_withdrawal().unwrap_err().unwrap();
    assert_eq!(err, ContractError::NotRollingBond);

    // Rolling bond: first request succeeds, second fails with WithdrawalAlreadyRequested
    let _rb = client.create_bond_with_rolling(&owner, &100_i128, &1000_u64, &true, &10_u64);
    let _ = client.request_withdrawal();
    let err2 = client.try_request_withdrawal().unwrap_err().unwrap();
    assert_eq!(err2, ContractError::WithdrawalAlreadyRequested);
}
