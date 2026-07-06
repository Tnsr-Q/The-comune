use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Local, non-replicated belief layer.
/// This never decides whether a valid packet merges.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TrustProfile {
    pub accepted_packets: u64,
    pub rejected_packets: u64,
    pub challenge_losses: u64,
    pub shadowed_writes: u64,
    pub trust_score: f64,
}

impl Default for TrustProfile {
    fn default() -> Self {
        Self {
            accepted_packets: 0,
            rejected_packets: 0,
            challenge_losses: 0,
            shadowed_writes: 0,
            trust_score: 0.5,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct BeliefLayer {
    pub profiles: BTreeMap<String, TrustProfile>,
}

impl BeliefLayer {
    pub fn profile_mut(&mut self, agent: &str) -> &mut TrustProfile {
        self.profiles.entry(agent.to_string()).or_default()
    }

    pub fn should_surface_in_recall(&self, agent: &str, certified: bool) -> bool {
        let score = self
            .profiles
            .get(agent)
            .map(|p| p.trust_score)
            .unwrap_or(0.5);
        score >= 0.70 || certified
    }
}
