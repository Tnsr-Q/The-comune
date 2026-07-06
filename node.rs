use crate::belief::BeliefLayer;
use crate::error::{AgentZkError, Result};
use crate::graph::{GraphDelta, GraphState};
use crate::hash::{b3, B3};
use crate::merge::{MergeEngine, MergePolicy};
use crate::packet::{DeltaRef, PckpPacket};
use ed25519_dalek::VerifyingKey;

#[derive(Clone, Debug)]
pub struct AgentZkNode {
    pub id: String,
    pub schema_hash: B3,
    pub policy_hash: B3,
    pub graph: GraphState,
    pub merge: MergeEngine,
    pub belief: BeliefLayer,
    pub wal: Vec<PckpPacket>,
}

impl AgentZkNode {
    pub fn new(id: impl Into<String>, schema_hash: B3, policy_hash: B3) -> Self {
        let merge = MergeEngine::new(MergePolicy::new(schema_hash, policy_hash));
        Self {
            id: id.into(),
            schema_hash,
            policy_hash,
            graph: GraphState::default(),
            merge,
            belief: BeliefLayer::default(),
            wal: Vec::new(),
        }
    }

    pub fn ingest(
        &mut self,
        packet: PckpPacket,
        verifying_key: &VerifyingKey,
        detached_delta: Option<Vec<u8>>,
    ) -> Result<()> {
        packet.verify(verifying_key)?;

        if packet.body.schema != self.schema_hash {
            return Err(AgentZkError::SchemaMismatch {
                expected: hex::encode(self.schema_hash),
                got: hex::encode(packet.body.schema),
            });
        }

        let delta_bytes = match &packet.body.delta {
            DeltaRef::Inline(bytes) => bytes.clone(),
            DeltaRef::Detached { hash, len } => {
                let bytes = detached_delta.ok_or(AgentZkError::MissingDeltaBody)?;
                if b3(&bytes) != *hash || bytes.len() != *len as usize {
                    return Err(AgentZkError::InvalidDelta);
                }
                bytes
            }
        };

        let delta: GraphDelta = postcard::from_bytes(&delta_bytes)
            .map_err(|e| AgentZkError::Serialization(e.to_string()))?;

        // Replication layer: objective checks passed, so merge.
        // Belief/trust affects recall, never convergence.
        self.merge.apply(&mut self.graph, &delta);
        self.belief.profile_mut(&packet.body.src).accepted_packets += 1;
        self.wal.push(packet);
        Ok(())
    }

    pub fn state_root(&self) -> B3 {
        self.graph.root()
    }
}
