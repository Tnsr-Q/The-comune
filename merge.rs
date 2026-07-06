use crate::graph::{GraphDelta, GraphState};
use crate::hash::B3;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergePolicy {
    pub schema_hash: B3,
    pub policy_hash: B3,
}

impl MergePolicy {
    pub fn new(schema_hash: B3, policy_hash: B3) -> Self {
        Self { schema_hash, policy_hash }
    }
}

/// Deterministic merge only.
/// No trust gates. No semantic contradiction detection. No LLM calls.
#[derive(Clone, Debug)]
pub struct MergeEngine {
    pub policy: MergePolicy,
}

impl MergeEngine {
    pub fn new(policy: MergePolicy) -> Self {
        Self { policy }
    }

    pub fn apply(&self, state: &mut GraphState, delta: &GraphDelta) {
        for patch in &delta.props {
            let entity = state.entity_mut(&patch.uid);
            match entity.props.get(&patch.key) {
                Some(existing) if existing.hlc > patch.register.hlc => {}
                Some(existing)
                    if existing.hlc == patch.register.hlc
                        && existing.writer > patch.register.writer => {}
                _ => {
                    entity.props.insert(patch.key.clone(), patch.register.clone());
                }
            }
        }

        for edge in &delta.edges {
            state.entity_mut(&edge.from).edges.insert(edge.clone());
        }
    }
}
