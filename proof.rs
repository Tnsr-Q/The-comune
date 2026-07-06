use crate::hash::{b3, B3};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofStatus {
    Uncertified,
    Certified,
    Anchored,
    Disputed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochRange {
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub state_root_before: B3,
    pub state_root_after: B3,
    pub packet_range_root: B3,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofReceipt {
    pub claim_type: String,
    pub range: EpochRange,
    pub receipt_hash: B3,
    pub status: ProofStatus,
}

#[derive(Clone, Debug, Default)]
pub struct FakeProofBackend;

impl FakeProofBackend {
    pub fn prove_transition(&self, range: EpochRange) -> ProofReceipt {
        let payload = serde_json::to_vec(&range).expect("range serialize");
        ProofReceipt {
            claim_type: "pckp.transition.v1".to_string(),
            range,
            receipt_hash: b3(payload),
            status: ProofStatus::Certified,
        }
    }
}
