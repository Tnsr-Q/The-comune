use crate::hash::{combine, B3};
use crate::hlc::Hlc;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropRegister {
    pub value: String,
    pub hlc: Hlc,
    pub tier: u8,
    pub writer: String,
    pub weight: u16,
}

impl PropRegister {
    pub fn new(value: impl Into<String>, hlc: Hlc, tier: u8, writer: impl Into<String>) -> Self {
        Self { value: value.into(), hlc, tier, writer: writer.into(), weight: 1 }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Edge {
    pub from: String,
    pub rel: String,
    pub to: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Entity {
    pub uid: String,
    pub props: BTreeMap<String, PropRegister>,
    pub edges: BTreeSet<Edge>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropPatch {
    pub uid: String,
    pub key: String,
    pub register: PropRegister,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct GraphDelta {
    pub props: Vec<PropPatch>,
    pub edges: Vec<Edge>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct GraphState {
    pub entities: BTreeMap<String, Entity>,
}

impl GraphState {
    pub fn entity_mut(&mut self, uid: &str) -> &mut Entity {
        self.entities.entry(uid.to_string()).or_insert_with(|| Entity {
            uid: uid.to_string(),
            ..Entity::default()
        })
    }

    pub fn root(&self) -> B3 {
        // Deterministic placeholder commitment.
        // Swap with real SMT later; tests already enforce convergence.
        let bytes = serde_json::to_vec(&self.entities).expect("graph serialize");
        combine("agentzk.graph.root.v0", &[&bytes])
    }
}
