use crate::graph::{GraphDelta, GraphState, PropRegister};
use crate::hash::B3;
use crate::hlc::Hlc;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

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

/// Envelope-derived merge context. The ONLY source of register metadata.
/// Constructed by the node from a signature-verified packet — never from delta contents.
#[derive(Clone, Copy, Debug)]
pub struct MergeCtx {
    pub hlc: Hlc,
    pub tier: u8,
    pub writer: [u8; 8], // b3(src)[..8]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RegisterLaw {
    LastWriteWins,  // mutable classes: max key wins
    FirstWriteWins, // append-only classes: min key wins — immutability by shadowing
}

fn class_of(uid: &str) -> &str {
    uid.split(':').next().unwrap_or("")
}

fn law_for(uid: &str) -> RegisterLaw {
    match class_of(uid) {
        "fact" | "episode" | "attestation" | "score" => RegisterLaw::FirstWriteWins,
        _ => RegisterLaw::LastWriteWins,
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct MergeReport {
    pub props_applied: usize,
    pub props_shadowed: usize, // losers — incl. immutability-violation attempts
    pub edges_added: usize,
}

/// Deterministic merge only. No trust gates, no semantic logic, no rejection paths:
/// every valid packet folds into state the same way in every order.
#[derive(Clone, Debug)]
pub struct MergeEngine {
    pub policy: MergePolicy,
}

impl MergeEngine {
    pub fn new(policy: MergePolicy) -> Self {
        Self { policy }
    }

    pub fn apply(&self, state: &mut GraphState, delta: &GraphDelta, ctx: &MergeCtx) -> MergeReport {
        let mut report = MergeReport::default();

        for patch in &delta.props {
            let incoming = PropRegister {
                value: patch.value.clone(),
                hlc: ctx.hlc,
                tier: ctx.tier,
                writer: ctx.writer,
            };
            let entity = state.entity_mut(&patch.uid);
            let wins = match entity.props.get(&patch.key) {
                None => true,
                Some(existing) => {
                    let inc = (incoming.hlc, incoming.tier, incoming.writer);
                    let cur = (existing.hlc, existing.tier, existing.writer);
                    match law_for(&patch.uid) {
                        RegisterLaw::LastWriteWins => match inc.cmp(&cur) {
                            Ordering::Greater => true,
                            Ordering::Less => false,
                            // equal keys ⇒ replay or equivocation; value bytes break the tie
                            Ordering::Equal => value_bytes(&incoming) > value_bytes(existing),
                        },
                        RegisterLaw::FirstWriteWins => match inc.cmp(&cur) {
                            Ordering::Less => true, // earlier write wins — always
                            Ordering::Greater => false,
                            Ordering::Equal => value_bytes(&incoming) < value_bytes(existing),
                        },
                    }
                }
            };
            if wins {
                entity.props.insert(patch.key.clone(), incoming);
                report.props_applied += 1;
            } else {
                report.props_shadowed += 1;
            }
        }

        for edge in &delta.edges {
            // add-wins set; MUST be a BTreeSet (root determinism — see P1-C)
            if state.entity_mut(&edge.from).edges.insert(edge.clone()) {
                report.edges_added += 1;
            }
        }

        report
    }
}

fn value_bytes(r: &PropRegister) -> Vec<u8> {
    // canonical byte comparison; avoids requiring Ord on value types (floats!)
    postcard::to_allocvec(&r.value).expect("prop value serializes")
}
