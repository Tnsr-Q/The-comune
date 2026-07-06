use agentzk_speedline::*;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;

fn packet(
    signer: &SigningKey,
    src: &str,
    schema: B3,
    seq: u64,
    hlc: Hlc,
    value: &str,
) -> PckpPacket {
    let delta = GraphDelta {
        props: vec![PropPatch {
            uid: "assessment:vendor-x".to_string(),
            key: "risk".to_string(),
            value: value.to_string(),
        }],
        edges: vec![],
    };
    let body = SignablePacket {
        v: 2,
        id: format!("pkt-{src}-{seq}"),
        src: src.to_string(),
        key: "skey:01".to_string(),
        swarm: "agentzk-alpha".to_string(),
        sess: Some("team:demo".to_string()),
        seq,
        prev: None,
        hlc,
        schema,
        delta: DeltaRef::from_bytes(postcard::to_allocvec(&delta).unwrap()),
        tier: 1,
        stake: None,
    };
    PckpPacket::sign(body, signer).unwrap()
}

fn main() {
    let schema = b3("jacobsen-schema:agentzk:v0.2");
    let policy = b3("merge-policy:deterministic-lww:v0.2");

    let researcher = SigningKey::generate(&mut OsRng);
    let auditor = SigningKey::generate(&mut OsRng);
    let researcher_src = "did:sol:researcher";
    let auditor_src = "did:sol:auditor";
    let t0 = 1_720_000_000_000;

    let pkt_researcher = packet(
        &researcher,
        researcher_src,
        schema,
        1,
        Hlc::new(t0, 0, nid_for(researcher_src)),
        "low",
    );
    let pkt_auditor = packet(
        &auditor,
        auditor_src,
        schema,
        1,
        Hlc::new(t0, 0, nid_for(auditor_src)),
        "high",
    );

    let mut node_a = AgentZkNode::new("node-a", schema, policy);
    let mut node_b = AgentZkNode::new("node-b", schema, policy);

    node_a
        .ingest(pkt_researcher.clone(), &researcher.verifying_key(), None)
        .unwrap();
    node_a
        .ingest(pkt_auditor.clone(), &auditor.verifying_key(), None)
        .unwrap();

    node_b
        .ingest(pkt_auditor, &auditor.verifying_key(), None)
        .unwrap();
    node_b
        .ingest(pkt_researcher, &researcher.verifying_key(), None)
        .unwrap();

    assert_eq!(node_a.state_root(), node_b.state_root());
    let winner = &node_a.graph.entities["assessment:vendor-x"].props["risk"].value;
    println!("winner = {winner}");
    println!("root = {}", hex::encode(node_a.state_root()));
}
