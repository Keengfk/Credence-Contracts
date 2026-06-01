#![cfg(test)]

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_bond_set_early_exit_dry_run() {
    let mut cmd = Command::cargo_bin("credence-admin").unwrap();
    cmd.arg("bond-set-early-exit-config")
        .arg("--bond-id")
        .arg("test-bond")
        .arg("--bps")
        .arg("500")
        .assert()
        .success()
        .stdout(predicate::str::contains("Dry run XDR:"));
}

#[test]
fn test_bond_set_weights_dry_run() {
    let mut cmd = Command::cargo_bin("credence-admin").unwrap();
    cmd.arg("bond-set-weights")
        .arg("--bond-id")
        .arg("test-bond")
        .arg("--weight")
        .arg("10")
        .assert()
        .success()
        .stdout(predicate::str::contains("Dry run XDR:"));
}
