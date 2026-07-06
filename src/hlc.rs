use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

/// Hybrid Logical Clock with node-id tiebreak.
/// Required for deterministic LWW across replicas.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct Hlc {
    pub physical_ms: u64,
    pub logical: u32,
    pub node_id: [u8; 8],
}

impl Hlc {
    pub fn new(physical_ms: u64, logical: u32, node_id: [u8; 8]) -> Self {
        Self {
            physical_ms,
            logical,
            node_id,
        }
    }

    pub fn tick(&self, now_ms: u64) -> Self {
        if now_ms > self.physical_ms {
            Self::new(now_ms, 0, self.node_id)
        } else {
            Self::new(self.physical_ms, self.logical + 1, self.node_id)
        }
    }
}

impl Ord for Hlc {
    fn cmp(&self, other: &Self) -> Ordering {
        self.physical_ms
            .cmp(&other.physical_ms)
            .then(self.logical.cmp(&other.logical))
            .then(self.node_id.cmp(&other.node_id))
    }
}

impl PartialOrd for Hlc {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
