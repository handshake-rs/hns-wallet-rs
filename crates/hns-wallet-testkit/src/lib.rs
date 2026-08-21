#![doc = "Deterministic, non-mainnet wallet qualification fixtures."]
#![forbid(unsafe_code)]

use hns_wallet_chain_api::Preimage;
use hns_wallet_market::{SwapSession, TimeoutPlan, VerifiedEvidence, VerifiedQuote};
use hns_wallet_types::{Amount, ModuleId, ObjectHash, SessionId, WalletAsset};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
pub const TEST_NOW_UNIX: u64 = 1_800_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeterministicNetwork {
    HandshakeRegtest,
    BitcoinRegtest,
    EthereumLocalDevelopment,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QualificationEvidence {
    pub unit_tests_passed: bool,
    pub restart_tests_passed: bool,
    pub reorg_tests_passed: bool,
    pub refund_tests_passed: bool,
    pub malicious_input_tests_passed: bool,
    pub real_network_demonstration_passed: bool,
    pub storage_benchmark_recorded: bool,
    pub bandwidth_benchmark_recorded: bool,
    pub independent_security_review_complete: bool,
}

impl QualificationEvidence {
    pub const fn unit_only() -> Self {
        Self {
            unit_tests_passed: true,
            restart_tests_passed: false,
            reorg_tests_passed: false,
            refund_tests_passed: false,
            malicious_input_tests_passed: true,
            real_network_demonstration_passed: false,
            storage_benchmark_recorded: false,
            bandwidth_benchmark_recorded: false,
            independent_security_review_complete: false,
        }
    }

    pub const fn permits_mainnet(&self) -> bool {
        self.unit_tests_passed
            && self.restart_tests_passed
            && self.reorg_tests_passed
            && self.refund_tests_passed
            && self.malicious_input_tests_passed
            && self.real_network_demonstration_passed
            && self.storage_benchmark_recorded
            && self.bandwidth_benchmark_recorded
            && self.independent_security_review_complete
    }
}

pub fn deterministic_preimage() -> Preimage {
    Preimage::new([42; 32])
}

pub fn deterministic_hashlock() -> ObjectHash {
    ObjectHash::new(Sha256::digest([42; 32]).into())
}

pub fn hns_btc_session() -> SwapSession {
    SwapSession::new(
        SessionId::new([2; 32]),
        ModuleId::Handshake,
        ModuleId::Bitcoin,
        VerifiedQuote {
            terms_id: ObjectHash::new([3; 32]),
            offered: Amount::new(WalletAsset::Hns, 1_000_000),
            received: Amount::new(WalletAsset::Btc, 10_000),
            valid_until_unix: TEST_NOW_UNIX + 600,
        },
        deterministic_hashlock(),
        TimeoutPlan {
            first_chain_refund_at: TEST_NOW_UNIX + 14_400,
            second_chain_refund_at: TEST_NOW_UNIX + 7_200,
            minimum_safety_margin: 3_600,
        },
        TEST_NOW_UNIX,
    )
    .expect("valid deterministic HNS/BTC session")
}

pub fn verified_funding_evidence(tag: u8) -> VerifiedEvidence {
    VerifiedEvidence::FirstFundingConfirmed {
        evidence: ObjectHash::new([tag; 32]),
    }
}

pub fn hostile_provider_requests() -> Vec<Value> {
    vec![
        json!({"method": "wallet_exportSeed", "params": {}}),
        json!({"method": "eth_sendTransaction", "params": {"data": "0xdeadbeef"}}),
        json!({"method": "wallet_addEthereumChain", "params": {}}),
        json!({"method": "wallet_signRawTransaction", "params": {}}),
        json!({"method": "nativeHost_execute", "params": {"command": "sh"}}),
    ]
}

pub fn malformed_wire_messages() -> Vec<Vec<u8>> {
    vec![
        Vec::new(),
        vec![0xff],
        vec![0; 1_048_577],
        b"{\"version\":999999999999999999999999}".to_vec(),
    ]
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReorgFixture {
    pub old_tip: u64,
    pub common_ancestor: u64,
    pub replacement_tip: u64,
    pub orphaned_evidence: Vec<ObjectHash>,
}

pub fn shallow_reorg_fixture() -> ReorgFixture {
    ReorgFixture {
        old_tip: 110,
        common_ancestor: 107,
        replacement_tip: 112,
        orphaned_evidence: vec![ObjectHash::new([9; 32]), ObjectHash::new([10; 32])],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_evidence_never_enables_mainnet() {
        assert!(!QualificationEvidence::unit_only().permits_mainnet());
    }

    #[test]
    fn fixtures_are_non_mainnet_and_deterministic() {
        assert_eq!(deterministic_hashlock(), deterministic_hashlock());
        assert_eq!(hns_btc_session(), hns_btc_session());
        assert_eq!(shallow_reorg_fixture().common_ancestor, 107);
    }

    #[test]
    fn hostile_corpus_includes_key_and_generic_evm_requests() {
        let methods: Vec<_> = hostile_provider_requests()
            .into_iter()
            .map(|value| value["method"].as_str().unwrap().to_owned())
            .collect();
        assert!(methods.contains(&"wallet_exportSeed".to_owned()));
        assert!(methods.contains(&"eth_sendTransaction".to_owned()));
    }
}
