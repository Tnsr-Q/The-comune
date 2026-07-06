use agentzk_speedline::*;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;

fn main() {
    let schema = b3("jacobsen-schema:agentzk:v0.2");
    let policy = b3("merge-policy:deterministic-lww:v0.2");

    let signer = SigningKey::generate(&mut OsRng);
    let verify = signer.verifying_key();

    let src = "did:sol:agent-researcher";
    let hlc = Hlc::new(1_720_000_000_000, 0, nid_for(src));

    let delta = GraphDelta {
        props: vec![PropPatch {
            uid: "fact:vendor-risk-001".to_string(),
            key: "statement".to_string(),
            value: "Vendor X has a Q3 invoice spike.".to_string(),
        }],
        edges: vec![Edge {
            from: "fact:vendor-risk-001".to_string(),
            rel: "OBSERVED_BY".to_string(),
            to: "agent:researcher".to_string(),
            hlc,
        }],
    };

    let body = SignablePacket {
        v: 2,
        id: "pkt-demo-001".to_string(),
        src: src.to_string(),
        key: "skey:01".to_string(),
        swarm: "agentzk-alpha".to_string(),
        sess: Some("team:demo".to_string()),
        seq: 1,
        prev: None,
        hlc,
        schema,
        delta: DeltaRef::from_bytes(postcard::to_allocvec(&delta).unwrap()),
        tier: 1,
        stake: Some("pda:stake:demo".to_string()),
    };

    let pkt = PckpPacket::sign(body, &signer).unwrap();

    let mut node_a = AgentZkNode::new("node-a", schema, policy);
    let mut node_b = AgentZkNode::new("node-b", schema, policy);

    node_a.ingest(pkt.clone(), &verify, None).unwrap();
    node_b.ingest(pkt, &verify, None).unwrap();

    println!("node_a_root = {}", hex::encode(node_a.state_root()));
    println!("node_b_root = {}", hex::encode(node_b.state_root()));
    assert_eq!(node_a.state_root(), node_b.state_root());
}
