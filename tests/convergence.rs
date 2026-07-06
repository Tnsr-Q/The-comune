use agentzk_speedline::*;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;

fn delta_set(uid: &str, key: &str, value: &str, hlc: Hlc, writer: &str) -> GraphDelta {
    GraphDelta {
        props: vec![PropPatch {
            uid: uid.to_string(),
            key: key.to_string(),
            register: PropRegister::new(value, hlc, 1, writer),
        }],
        edges: vec![],
    }
}

fn packet(delta: GraphDelta, seq: u64, hlc: Hlc, schema: B3, signer: &SigningKey, src: &str) -> PckpPacket {
    let bytes = postcard::to_allocvec(&delta).unwrap();
    let body = SignablePacket {
        v: 2,
        id: format!("pkt-{seq}"),
        src: src.to_string(),
        key: "skey:01".to_string(),
        swarm: "alpha".to_string(),
        sess: Some("team:test".to_string()),
        seq,
        prev: None,
        hlc,
        schema,
        delta: DeltaRef::from_bytes(bytes),
        tier: 1,
        stake: None,
    };
    PckpPacket::sign(body, signer).unwrap()
}

#[test]
fn lww_converges_under_different_packet_orders() {
    let schema = b3("schema:v1");
    let policy = b3("policy:v1");
    let signer = SigningKey::generate(&mut OsRng);
    let verify = signer.verifying_key();

    let p1 = packet(
        delta_set("entity:1", "name", "old", Hlc::new(1000, 0, *b"nodeA000"), "agent:a"),
        1,
        Hlc::new(1000, 0, *b"nodeA000"),
        schema,
        &signer,
        "agent:a",
    );

    let p2 = packet(
        delta_set("entity:1", "name", "new", Hlc::new(1001, 0, *b"nodeB000"), "agent:b"),
        2,
        Hlc::new(1001, 0, *b"nodeB000"),
        schema,
        &signer,
        "agent:b",
    );

    let mut n1 = AgentZkNode::new("n1", schema, policy);
    let mut n2 = AgentZkNode::new("n2", schema, policy);

    n1.ingest(p1.clone(), &verify, None).unwrap();
    n1.ingest(p2.clone(), &verify, None).unwrap();

    n2.ingest(p2, &verify, None).unwrap();
    n2.ingest(p1, &verify, None).unwrap();

    assert_eq!(n1.state_root(), n2.state_root());
    assert_eq!(n1.graph.entities["entity:1"].props["name"].value, "new");
}

#[test]
fn low_trust_does_not_block_replication() {
    let schema = b3("schema:v1");
    let policy = b3("policy:v1");
    let signer = SigningKey::generate(&mut OsRng);
    let verify = signer.verifying_key();

    let p = packet(
        delta_set("fact:low-trust", "statement", "Still replicated.", Hlc::new(1, 0, *b"nodeC000"), "agent:low"),
        1,
        Hlc::new(1, 0, *b"nodeC000"),
        schema,
        &signer,
        "agent:low",
    );

    let mut node = AgentZkNode::new("n1", schema, policy);
    node.belief.profile_mut("agent:low").trust_score = 0.01;

    node.ingest(p, &verify, None).unwrap();

    assert!(node.graph.entities.contains_key("fact:low-trust"));
    assert!(!node.belief.should_surface_in_recall("agent:low", false));
}
