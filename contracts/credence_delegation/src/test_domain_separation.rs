//! Domain-separation and replay attack tests for delegated execution.
//!
//! These tests verify that:
//!
//! 1. A payload signed for one domain (e.g. `Delegate`) cannot be replayed
//!    against a different domain (e.g. `RevokeDelegation`).
//! 2. A payload carrying the wrong `contract_id` is rejected.
//! 3. A stale / replayed nonce is rejected after it has been consumed.
//! 4. The nonce increments correctly after each delegated call.
//! 5. Cross-method replay: a revoke payload cannot be reused as a delegate payload.

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::Env;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn setup() -> (Env, CredenceDelegationClient<'static>, Address) {
    let e = Env::default();
    e.mock_all_auths();
    let contract_id = e.register(CredenceDelegation, ());
    let client = CredenceDelegationClient::new(&e, &contract_id);
    let admin = Address::generate(&e);
    client.initialize(&admin);
    (e, client, contract_id)
}

/// Build a valid `DelegatedActionPayload` for the given parameters.
fn make_payload(
    _e: &Env,
    domain: DomainTag,
    owner: &Address,
    target: &Address,
    contract_id: &Address,
    nonce: u64,
) -> DelegatedActionPayload {
    DelegatedActionPayload {
        domain,
        owner: owner.clone(),
        target: target.clone(),
        contract_id: contract_id.clone(),
        nonce,
    }
}

// ---------------------------------------------------------------------------
// Nonce baseline
// ---------------------------------------------------------------------------

#[test]
fn nonce_starts_at_zero() {
    let (e, client, _) = setup();
    let owner = Address::generate(&e);
    assert_eq!(client.get_nonce(&owner), 0);
}

#[test]
fn nonce_increments_after_delegated_delegate() {
    let (e, client, contract_id) = setup();
    let owner = Address::generate(&e);
    let delegate = Address::generate(&e);
    let expiry = e.ledger().timestamp() + 86_400;

    let payload = make_payload(&e, DomainTag::Delegate, &owner, &delegate, &contract_id, 0);
    client.execute_delegated_delegate(
        &owner,
        &delegate,
        &DelegationType::Attestation,
        &expiry,
        &payload,
    );
    assert_eq!(client.get_nonce(&owner), 1);

    let payload2 = make_payload(&e, DomainTag::Delegate, &owner, &delegate, &contract_id, 1);
    client.execute_delegated_delegate(
        &owner,
        &delegate,
        &DelegationType::Management,
        &expiry,
        &payload2,
    );
    assert_eq!(client.get_nonce(&owner), 2);
}

// ---------------------------------------------------------------------------
// Cross-domain replay: Delegate payload used in RevokeDelegation
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #208)")]
fn cross_domain_replay_delegate_payload_in_revoke() {
    let (e, client, contract_id) = setup();
    let owner = Address::generate(&e);
    let delegate = Address::generate(&e);
    let expiry = e.ledger().timestamp() + 86_400;

    // Build a valid *Delegate* payload
    let delegate_payload =
        make_payload(&e, DomainTag::Delegate, &owner, &delegate, &contract_id, 0);

    // Use it to create the delegation normally
    client.execute_delegated_delegate(
        &owner,
        &delegate,
        &DelegationType::Attestation,
        &expiry,
        &delegate_payload,
    );

    // Now build a *new* Delegate-tagged payload (wrong domain) and try to
    // pass it to execute_delegated_revoke.  This simulates an attacker
    // replaying or repurposing the same payload type.
    let wrong_domain_payload =
        make_payload(&e, DomainTag::Delegate, &owner, &delegate, &contract_id, 1);

    client.execute_delegated_revoke(
        &owner,
        &delegate,
        &DelegationType::Attestation,
        &wrong_domain_payload,
    );
}

// ---------------------------------------------------------------------------
// Cross-domain replay: RevokeDelegation payload used in Delegate
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #208)")]
fn cross_domain_replay_revoke_payload_in_delegate() {
    let (e, client, contract_id) = setup();
    let owner = Address::generate(&e);
    let delegate = Address::generate(&e);
    let expiry = e.ledger().timestamp() + 86_400;

    // Attacker builds a RevokeDelegation payload and tries to use it to
    // *create* a delegation (swapped domain tag).
    let wrong_domain_payload = make_payload(
        &e,
        DomainTag::RevokeDelegation,
        &owner,
        &delegate,
        &contract_id,
        0,
    );

    client.execute_delegated_delegate(
        &owner,
        &delegate,
        &DelegationType::Attestation,
        &expiry,
        &wrong_domain_payload,
    );
}

// ---------------------------------------------------------------------------
// Cross-domain replay: Delegate payload used in RevokeAttestation
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #208)")]
fn cross_domain_replay_delegate_payload_in_revoke_attestation() {
    let (e, client, contract_id) = setup();
    let attester = Address::generate(&e);
    let subject = Address::generate(&e);

    // A Delegate-tagged payload routed to revoke_attestation should be blocked.
    let wrong_payload = make_payload(
        &e,
        DomainTag::Delegate,
        &attester,
        &subject,
        &contract_id,
        0,
    );

    client.execute_delegated_revoke_attest(&attester, &subject, &wrong_payload);
}

// ---------------------------------------------------------------------------
// Nonce replay: same nonce rejected twice in the same domain
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #208)")]
fn nonce_replay_rejected_same_domain() {
    let (e, client, contract_id) = setup();
    let owner = Address::generate(&e);
    let delegate = Address::generate(&e);
    let expiry = e.ledger().timestamp() + 86_400;

    let payload = make_payload(&e, DomainTag::Delegate, &owner, &delegate, &contract_id, 0);
    client.execute_delegated_delegate(
        &owner,
        &delegate,
        &DelegationType::Attestation,
        &expiry,
        &payload.clone(),
    );

    // Replay the *same* payload (nonce = 0 is now stale).
    client.execute_delegated_delegate(
        &owner,
        &delegate,
        &DelegationType::Management,
        &expiry,
        &payload,
    );
}

// ---------------------------------------------------------------------------
// Nonce replay: stale nonce across different domains
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #208)")]
fn nonce_replay_rejected_cross_domain_stale_nonce() {
    let (e, client, contract_id) = setup();
    let owner = Address::generate(&e);
    let delegate = Address::generate(&e);
    let expiry = e.ledger().timestamp() + 86_400;

    // Consume nonce 0 via the delegate path
    let p1 = make_payload(&e, DomainTag::Delegate, &owner, &delegate, &contract_id, 0);
    client.execute_delegated_delegate(
        &owner,
        &delegate,
        &DelegationType::Attestation,
        &expiry,
        &p1,
    );

    // Attacker attempts to use nonce 0 on the revoke path (stale nonce)
    let p2 = make_payload(
        &e,
        DomainTag::RevokeDelegation,
        &owner,
        &delegate,
        &contract_id,
        0,
    );
    client.execute_delegated_revoke(&owner, &delegate, &DelegationType::Attestation, &p2);
}

// ---------------------------------------------------------------------------
// Wrong contract_id (cross-contract / cross-deployment replay)
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #208)")]
fn cross_contract_replay_rejected() {
    let (e, client, _) = setup();
    let owner = Address::generate(&e);
    let delegate = Address::generate(&e);
    let expiry = e.ledger().timestamp() + 86_400;

    // Use a *different* (fake) contract address in the payload
    let fake_contract = Address::generate(&e);
    let payload = make_payload(
        &e,
        DomainTag::Delegate,
        &owner,
        &delegate,
        &fake_contract,
        0,
    );

    client.execute_delegated_delegate(
        &owner,
        &delegate,
        &DelegationType::Attestation,
        &expiry,
        &payload,
    );
}

// ---------------------------------------------------------------------------
// Wrong owner in payload
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #208)")]
fn wrong_owner_in_payload_rejected() {
    let (e, client, contract_id) = setup();
    let real_owner = Address::generate(&e);
    let attacker = Address::generate(&e);
    let delegate = Address::generate(&e);
    let expiry = e.ledger().timestamp() + 86_400;

    // Payload says `attacker` but the call passes `real_owner`
    let payload = make_payload(
        &e,
        DomainTag::Delegate,
        &attacker,
        &delegate,
        &contract_id,
        0,
    );

    client.execute_delegated_delegate(
        &real_owner,
        &delegate,
        &DelegationType::Attestation,
        &expiry,
        &payload,
    );
}

// ---------------------------------------------------------------------------
// Wrong target in payload
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #208)")]
fn wrong_target_in_payload_rejected() {
    let (e, client, contract_id) = setup();
    let owner = Address::generate(&e);
    let delegate = Address::generate(&e);
    let different_target = Address::generate(&e);
    let expiry = e.ledger().timestamp() + 86_400;

    // Payload says `different_target` but the call passes `delegate`
    let payload = make_payload(
        &e,
        DomainTag::Delegate,
        &owner,
        &different_target,
        &contract_id,
        0,
    );

    client.execute_delegated_delegate(
        &owner,
        &delegate,
        &DelegationType::Attestation,
        &expiry,
        &payload,
    );
}

// ---------------------------------------------------------------------------
// Happy path: full delegated round-trip (delegate → revoke)
// ---------------------------------------------------------------------------

#[test]
fn partial_nonce_invalidation_skips_range_and_allows_next_nonce() {
    let (e, client, contract_id) = setup();
    let owner = Address::generate(&e);
    let delegate = Address::generate(&e);
    let expiry = e.ledger().timestamp() + 86_400;

    // Consume nonces 0 and 1 normally.
    let p0 = make_payload(&e, DomainTag::Delegate, &owner, &delegate, &contract_id, 0);
    client.execute_delegated_delegate(
        &owner,
        &delegate,
        &DelegationType::Attestation,
        &expiry,
        &p0,
    );
    let p1 = make_payload(&e, DomainTag::Delegate, &owner, &delegate, &contract_id, 1);
    client.execute_delegated_delegate(&owner, &delegate, &DelegationType::Management, &expiry, &p1);
    assert_eq!(client.get_nonce(&owner), 2);

    // Invalidate [2, 4): nonce 2 and 3 become unusable.
    client.invalidate_nonce_range(&owner, &4);
    assert_eq!(client.get_nonce(&owner), 4);

    // Fresh nonce 4 must still be usable.
    let p4 = make_payload(&e, DomainTag::Delegate, &owner, &delegate, &contract_id, 4);
    client.execute_delegated_delegate(
        &owner,
        &delegate,
        &DelegationType::Attestation,
        &expiry,
        &p4,
    );
    assert_eq!(client.get_nonce(&owner), 5);
}

#[test]
#[should_panic(expected = "Error(Contract, #208)")]
fn full_nonce_invalidation_rejects_previously_valid_payload() {
    let (e, client, contract_id) = setup();
    let owner = Address::generate(&e);
    let delegate = Address::generate(&e);
    let expiry = e.ledger().timestamp() + 86_400;

    // This payload is valid at nonce 0 before invalidation.
    let stale_payload = make_payload(&e, DomainTag::Delegate, &owner, &delegate, &contract_id, 0);

    // Invalidate a full early range [0, 10).
    client.invalidate_nonce_range(&owner, &10);
    assert_eq!(client.get_nonce(&owner), 10);

    // Previously valid payload must now fail.
    client.execute_delegated_delegate(
        &owner,
        &delegate,
        &DelegationType::Attestation,
        &expiry,
        &stale_payload,
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #208)")]
fn nonce_invalidation_range_bound_enforced() {
    let (e, client, _) = setup();
    let owner = Address::generate(&e);

    // MAX_NONCE_INVALIDATION_SPAN is 10_000, so 10_001 must fail from nonce 0.
    client.invalidate_nonce_range(&owner, &10_001);
}

#[test]
#[should_panic(expected = "Error(Contract, #208)")]
fn nonce_invalidation_must_be_monotonic() {
    let (e, client, _) = setup();
    let owner = Address::generate(&e);

    client.invalidate_nonce_range(&owner, &1);
    // Reusing the same target is non-monotonic and must fail.
    client.invalidate_nonce_range(&owner, &1);
}

#[test]
fn happy_path_delegated_delegate_then_revoke() {
    let (e, client, contract_id) = setup();
    let owner = Address::generate(&e);
    let delegate = Address::generate(&e);
    let expiry = e.ledger().timestamp() + 86_400;

    // Step 1: create delegation via relayer
    let p1 = make_payload(&e, DomainTag::Delegate, &owner, &delegate, &contract_id, 0);
    let d = client.execute_delegated_delegate(
        &owner,
        &delegate,
        &DelegationType::Attestation,
        &expiry,
        &p1,
    );
    assert!(!d.revoked);
    assert_eq!(client.get_nonce(&owner), 1);

    // Step 2: revoke via relayer using correct domain + fresh nonce
    let p2 = make_payload(
        &e,
        DomainTag::RevokeDelegation,
        &owner,
        &delegate,
        &contract_id,
        1,
    );
    client.execute_delegated_revoke(&owner, &delegate, &DelegationType::Attestation, &p2);
    assert_eq!(client.get_nonce(&owner), 2);

    // Delegation must now be marked revoked
    let d2 = client.get_delegation(&owner, &delegate, &DelegationType::Attestation);
    assert!(d2.revoked);
}

// ---------------------------------------------------------------------------
// Happy path: delegated revoke_attestation
// ---------------------------------------------------------------------------

#[test]
fn happy_path_delegated_revoke_attestation() {
    let (e, client, contract_id) = setup();
    let attester = Address::generate(&e);
    let subject = Address::generate(&e);
    let expiry = e.ledger().timestamp() + 86_400;

    // Create the attestation entry first (direct path, no domain payload needed)
    client.delegate(&attester, &subject, &DelegationType::Attestation, &expiry, &0_u64);

    // Revoke via relayer
    let payload = make_payload(
        &e,
        DomainTag::RevokeAttestation,
        &attester,
        &subject,
        &contract_id,
        0,
    );
    client.execute_delegated_revoke_attest(&attester, &subject, &payload);

    assert!(matches!(
        client.get_attestation_status(&attester, &subject),
        AttestationStatus::Revoked
    ));
    assert_eq!(client.get_nonce(&attester), 1);
}

#[test]
fn test_direct_path_nonce_reconciliation_and_invalidation() {
    let (e, client, contract_id) = setup();
    let owner = Address::generate(&e);
    let delegate = Address::generate(&e);
    let expiry = e.ledger().timestamp() + 86_400;

    // 1. Direct path action consumes sequence 0
    assert_eq!(client.get_nonce(&owner), 0);
    client.delegate(
        &owner,
        &delegate,
        &DelegationType::Attestation,
        &expiry,
        &0_u64,
    );
    assert_eq!(client.get_nonce(&owner), 1);

    // 2. Direct path action fails if reusing sequence 0
    let res = client.try_delegate(
        &owner,
        &delegate,
        &DelegationType::Management,
        &expiry,
        &0_u64,
    );
    assert!(
        res.is_err(),
        "Expected rejection of stale sequence on direct execution"
    );

    // 3. Trigger range invalidation mechanism to bounce current sequence to index 5
    client.invalidate_nonce_range(&owner, &5_u64);
    assert_eq!(client.get_nonce(&owner), 5);

    // 4. Stale execution attempt at historical gap index fails
    let res_stale = client.try_delegate(
        &owner,
        &delegate,
        &DelegationType::Management,
        &expiry,
        &1_u64,
    );
    assert!(res_stale.is_err());

    // 5. Valid transaction successfully locks in sequence sequence index 5
    client.delegate(
        &owner,
        &delegate,
        &DelegationType::Management,
        &expiry,
        &5_u64,
    );
    assert_eq!(client.get_nonce(&owner), 6);
}

#[test]
fn test_mixed_execution_interleaving() {
    let (e, client, contract_id) = setup();
    let owner = Address::generate(&e);
    let delegate = Address::generate(&e);
    let expiry = e.ledger().timestamp() + 86_400;

    // Direct invocation uses 0
    client.delegate(
        &owner,
        &delegate,
        &DelegationType::Attestation,
        &expiry,
        &0_u64,
    );

    // Relayer off-chain action relies on index 1
    let payload = make_payload(
        &e,
        DomainTag::RevokeDelegation,
        &owner,
        &delegate,
        &contract_id,
        1,
    );
    client.execute_delegated_revoke(&owner, &delegate, &DelegationType::Attestation, &payload);

    assert_eq!(client.get_nonce(&owner), 2);
}
