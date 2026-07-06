use crate::belief::BeliefLayer;
use crate::error::{AgentZkError, Result};
use crate::graph::{GraphDelta, GraphState};
use crate::hash::{b3, B3};
use crate::merge::{MergeCtx, MergeEngine, MergePolicy};
use crate::packet::{DeltaRef, PckpPacket};
use ed25519_dalek::VerifyingKey;
use std::collections::{BTreeMap, HashMap, HashSet};

pub const MAX_DELTA_LEN: usize = 128 * 1024;
pub const MAX_PENDING_PER_SRC: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ack {
    Merged,
    Duplicate, // idempotent no-op: state untouched, wal untouched, belief untouched
    Parked,    // future seq held back awaiting chain predecessors
}

/// Binds src DIDs to registered keys. Local registry now; AgentIdentity PDA later.
pub trait KeyResolver {
    fn resolve(&self, src: &str, key_ref: &str) -> Result<VerifyingKey>;
}

#[derive(Clone, Debug, Default)]
struct ChainState {
    last_seq: u64,
    last_hash: B3,
    by_seq: HashMap<u64, B3>, // equivocation detection
}

#[derive(Clone, Debug)]
pub struct AgentZkNode {
    pub id: String,
    pub schema_hash: B3,
    pub policy_hash: B3,
    pub graph: GraphState,
    pub merge: MergeEngine,
    pub belief: BeliefLayer,
    pub wal: Vec<PckpPacket>,
    seen: HashSet<B3>,
    chains: HashMap<String, ChainState>,
    pending: HashMap<String, BTreeMap<u64, (PckpPacket, Option<Vec<u8>>)>>,
    pub equivocation_evidence: Vec<(B3, B3)>, // (hash_a, hash_b) same (src, seq) — SLASH-EQUIV seed
}

pub fn nid_for(src: &str) -> [u8; 8] {
    b3(src.as_bytes())[..8].try_into().unwrap()
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
            seen: HashSet::new(),
            chains: HashMap::new(),
            pending: HashMap::new(),
            equivocation_evidence: Vec::new(),
        }
    }

    pub fn ingest<R: KeyResolver>(
        &mut self,
        packet: PckpPacket,
        resolver: &R,
        detached_delta: Option<Vec<u8>>,
    ) -> Result<Ack> {
        // 1. Key binding: the key comes from the registry, keyed by the CLAIMED src.
        //    A signature by any other key now fails here. (P0-D)
        let vk = resolver.resolve(&packet.body.src, &packet.body.key)?;
        packet.verify(&vk)?;

        // 2. Dedup — before any counters or wal move. (P1-A)
        let ch = packet.content_hash();
        if self.seen.contains(&ch) {
            return Ok(Ack::Duplicate);
        }

        // 3. nid ↔ src binding (F3)
        if packet.body.hlc.nid != nid_for(&packet.body.src) {
            return Err(AgentZkError::NidMismatch);
        }

        // 4. Schema
        if packet.body.schema != self.schema_hash {
            return Err(AgentZkError::SchemaMismatch {
                expected: hex::encode(self.schema_hash),
                got: hex::encode(packet.body.schema),
            });
        }

        // 5. Size caps (E_SIZE) — before clone/parse of anything big
        let declared_len = match &packet.body.delta {
            DeltaRef::Inline(bytes) => bytes.len(),
            DeltaRef::Detached { len, .. } => *len as usize,
        };
        if declared_len > MAX_DELTA_LEN {
            return Err(AgentZkError::DeltaTooLarge(declared_len));
        }

        // 6. Seq chain (P1-B)
        let src = packet.body.src.clone();
        let chain = self.chains.entry(src.clone()).or_default();
        if let Some(prev_hash) = chain.by_seq.get(&packet.body.seq) {
            if *prev_hash != ch {
                // same (src, seq), different content: equivocation. Keep BOTH as evidence.
                self.equivocation_evidence.push((*prev_hash, ch));
                return Err(AgentZkError::Equivocation { src, seq: packet.body.seq });
            }
            return Ok(Ack::Duplicate);
        }
        let expected = chain.last_seq + 1;
        if packet.body.seq > expected {
            // Future packet: park it. Hold-back is what keeps seq enforcement
            // compatible with permutation convergence.
            let slot = self.pending.entry(src).or_default();
            if slot.len() >= MAX_PENDING_PER_SRC {
                return Err(AgentZkError::PendingOverflow);
            }
            slot.insert(packet.body.seq, (packet, detached_delta));
            return Ok(Ack::Parked);
        }
        if packet.body.seq == expected && packet.body.prev != Some(chain.last_hash).filter(|_| chain.last_seq > 0) {
            // seq 1 must have prev = None; seq n must chain to hash(n-1)
            if !(packet.body.seq == 1 && packet.body.prev.is_none()) {
                return Err(AgentZkError::ChainBreak { src, seq: packet.body.seq });
            }
        }

        // 7. Delta binding (F2) + decode
        let delta_bytes = match &packet.body.delta {
            DeltaRef::Inline(bytes) => bytes.clone(), // covered by signature directly
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

        // 8. Merge — metadata derived from the VERIFIED envelope, nowhere else. (P0-A)
        let ctx = MergeCtx {
            hlc: packet.body.hlc,
            tier: packet.body.tier,
            writer: nid_for(&packet.body.src),
        };
        let report = self.merge.apply(&mut self.graph, &delta, &ctx);

        // 9. Bookkeeping — only after full acceptance
        let chain = self.chains.get_mut(&packet.body.src).unwrap();
        chain.last_seq = packet.body.seq;
        chain.last_hash = ch;
        chain.by_seq.insert(packet.body.seq, ch);
        self.seen.insert(ch);
        let profile = self.belief.profile_mut(&packet.body.src);
        profile.accepted_packets += 1;
        if report.props_shadowed > 0 {
            profile.shadowed_writes += report.props_shadowed as u64; // FWW violation attempts show up here
        }
        self.wal.push(packet.clone());

        // 10. Drain any parked successors now unblocked
        self.drain_pending(&packet.body.src, resolver);
        Ok(Ack::Merged)
    }

    fn drain_pending<R: KeyResolver>(&mut self, src: &str, resolver: &R) {
        loop {
            let next_seq = self.chains.get(src).map(|c| c.last_seq + 1).unwrap_or(1);
            let Some((pkt, delta)) = self.pending.get_mut(src).and_then(|m| m.remove(&next_seq)) else {
                return;
            };
            if self.ingest(pkt, resolver, delta).is_err() {
                return; // bad parked packet: stop draining; chain stalls until valid successor
            }
        }
    }

    pub fn state_root(&self) -> B3 {
        self.graph.root()
    }
}
