use agentzk_speedline::*;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use std::collections::HashMap;

#[derive(Default)]
struct Resolver(HashMap<String, VerifyingKey>);

impl KeyResolver for Resolver {
    fn resolve(&self, src: &str, _key_ref: &str) -> Result<VerifyingKey> {
        self.0
            .get(src)
            .copied()
            .ok_or_else(|| AgentZkError::Serialization(format!("missing key for {src}")))
    }
}

fn delta_prop(uid: &str, key: &str, value: &str) -> GraphDelta {
    GraphDelta {
        props: vec![PropPatch {
            uid: uid.to_string(),
            key: key.to_string(),
            value: value.to_string(),
        }],
        edges: vec![],
    }
}

fn delta_edge(from: &str, rel: &str, to: &str) -> GraphDelta {
    GraphDelta {
        props: vec![],
        edges: vec![Edge {
            from: from.to_string(),
            rel: rel.to_string(),
            to: to.to_string(),
            hlc: Hlc::new(0, 0, [0; 8]),
        }],
    }
}

fn sign_packet(
    delta: &GraphDelta,
    seq: u64,
    prev: Option<B3>,
    physical_ms: u64,
    signer: &SigningKey,
    src: &str,
    schema: B3,
) -> PckpPacket {
    let hlc = Hlc::new(physical_ms, 0, nid_for(src));
    let body = SignablePacket {
        v: 2,
        id: format!("{src}-{seq}"),
        src: src.to_string(),
        key: "skey:test".to_string(),
        swarm: "test".to_string(),
        sess: None,
        seq,
        prev,
        hlc,
        schema,
        delta: DeltaRef::from_bytes(postcard::to_allocvec(delta).unwrap()),
        tier: 1,
        stake: None,
    };
    PckpPacket::sign(body, signer).unwrap()
}

fn sign_detached_packet(
    delta_bytes: Vec<u8>,
    signer: &SigningKey,
    src: &str,
    schema: B3,
) -> PckpPacket {
    let body = SignablePacket {
        v: 2,
        id: "detached".to_string(),
        src: src.to_string(),
        key: "skey:test".to_string(),
        swarm: "test".to_string(),
        sess: None,
        seq: 1,
        prev: None,
        hlc: Hlc::new(10, 0, nid_for(src)),
        schema,
        delta: DeltaRef::Detached {
            hash: b3(&delta_bytes),
            len: delta_bytes.len() as u32,
        },
        tier: 1,
        stake: None,
    };
    PckpPacket::sign(body, signer).unwrap()
}

fn reverse_on_bit<T: Clone>(items: &[T], seed: u64) -> Vec<T> {
    let mut out = items.to_vec();
    for i in 0..out.len() {
        let j = ((seed.wrapping_mul(1_103_515_245).wrapping_add(i as u64)) as usize) % out.len();
        out.swap(i, j);
    }
    out
}

#[test]
fn permutation_convergence_with_conflicts_duplicates_edges_and_rejects() {
    let schema = b3("schema:issue5");
    let policy = b3("policy:issue5");
    let alice = SigningKey::generate(&mut OsRng);
    let bob = SigningKey::generate(&mut OsRng);
    let mut resolver = Resolver::default();
    resolver
        .0
        .insert("did:alice".to_string(), alice.verifying_key());
    resolver
        .0
        .insert("did:bob".to_string(), bob.verifying_key());

    let fact1 = sign_packet(
        &delta_prop("fact:stable", "statement", "first"),
        1,
        None,
        1,
        &alice,
        "did:alice",
        schema,
    );
    let immutable_violation = sign_packet(
        &delta_prop("fact:stable", "statement", "mutated"),
        2,
        Some(fact1.content_hash()),
        2,
        &alice,
        "did:alice",
        schema,
    );
    let bob_mutable = sign_packet(
        &delta_prop("assessment:vendor-x", "risk", "high"),
        1,
        None,
        7,
        &bob,
        "did:bob",
        schema,
    );
    let bob_edge = sign_packet(
        &delta_edge("assessment:vendor-x", "CITES", "fact:stable"),
        2,
        Some(bob_mutable.content_hash()),
        8,
        &bob,
        "did:bob",
        schema,
    );

    let corpus = vec![
        fact1.clone(),
        immutable_violation,
        bob_mutable.clone(),
        bob_edge,
        bob_mutable,
    ];
    let mut reference = None;
    for seed in 0..64 {
        let mut node = AgentZkNode::new(format!("node-{seed}"), schema, policy);
        for pkt in reverse_on_bit(&corpus, seed) {
            let _ = node.ingest(pkt, &resolver, None);
        }
        assert_eq!(
            node.graph.entities["fact:stable"].props["statement"].value,
            "first"
        );
        match reference {
            None => reference = Some(node.state_root()),
            Some(root) => assert_eq!(root, node.state_root(), "divergence at seed {seed}"),
        }
    }
}

#[test]
fn tampered_detached_delta_is_rejected() {
    let schema = b3("schema:issue5");
    let policy = b3("policy:issue5");
    let signer = SigningKey::generate(&mut OsRng);
    let src = "did:tamper";
    let delta_bytes = postcard::to_allocvec(&delta_prop("entity:1", "name", "ok")).unwrap();
    let pkt = sign_detached_packet(delta_bytes.clone(), &signer, src, schema);
    let mut tampered = delta_bytes;
    tampered[0] ^= 0xff;

    let mut node = AgentZkNode::new("node", schema, policy);
    assert!(matches!(
        node.ingest(pkt, &signer.verifying_key(), Some(tampered)),
        Err(AgentZkError::InvalidDelta)
    ));
}

#[test]
fn nid_mismatch_is_rejected() {
    let schema = b3("schema:issue5");
    let policy = b3("policy:issue5");
    let signer = SigningKey::generate(&mut OsRng);
    let delta = delta_prop("entity:1", "name", "ok");
    let mut pkt = sign_packet(&delta, 1, None, 10, &signer, "did:nid", schema);
    pkt.body.hlc.node_id = *b"forged!!";
    pkt = PckpPacket::sign(pkt.body, &signer).unwrap();

    let mut node = AgentZkNode::new("node", schema, policy);
    assert!(matches!(
        node.ingest(pkt, &signer.verifying_key(), None),
        Err(AgentZkError::NidMismatch)
    ));
}

#[test]
fn duplicate_ingest_is_noop() {
    let schema = b3("schema:issue5");
    let policy = b3("policy:issue5");
    let signer = SigningKey::generate(&mut OsRng);
    let pkt = sign_packet(
        &delta_prop("entity:dup", "name", "once"),
        1,
        None,
        10,
        &signer,
        "did:dup",
        schema,
    );
    let mut node = AgentZkNode::new("node", schema, policy);
    assert_eq!(
        node.ingest(pkt.clone(), &signer.verifying_key(), None)
            .unwrap(),
        Ack::Merged
    );
    let root = node.state_root();
    let wal_len = node.wal.len();
    assert_eq!(
        node.ingest(pkt, &signer.verifying_key(), None).unwrap(),
        Ack::Duplicate
    );
    assert_eq!(root, node.state_root());
    assert_eq!(wal_len, node.wal.len());
}

#[test]
fn equivocation_records_both_signed_packets() {
    let schema = b3("schema:issue5");
    let policy = b3("policy:issue5");
    let signer = SigningKey::generate(&mut OsRng);
    let src = "did:equiv";
    let pkt_a = sign_packet(
        &delta_prop("entity:e", "v", "a"),
        1,
        None,
        10,
        &signer,
        src,
        schema,
    );
    let pkt_b = sign_packet(
        &delta_prop("entity:e", "v", "b"),
        1,
        None,
        10,
        &signer,
        src,
        schema,
    );
    let mut node = AgentZkNode::new("node", schema, policy);
    node.ingest(pkt_a.clone(), &signer.verifying_key(), None)
        .unwrap();
    assert!(matches!(
        node.ingest(pkt_b.clone(), &signer.verifying_key(), None),
        Err(AgentZkError::Equivocation { .. })
    ));
    assert_eq!(node.equivocation_evidence.len(), 1);
    assert_eq!(
        node.equivocation_evidence[0].0.content_hash(),
        pkt_a.content_hash()
    );
    assert_eq!(
        node.equivocation_evidence[0].1.content_hash(),
        pkt_b.content_hash()
    );
}
