# AGENTZK-Speedline M0/M1 Scaffold

Speed-first shared-knowledge scaffold for SparrowDB-style nodes.

This implements the first two milestones:

- **M0:** deterministic merge-law property foundation
- **M1:** two-node signed PCKP packet merge/convergence demo

Design principles:
- ZK is async and epoch/range-based, never hot-path.
- Replication and belief are separate.
- Merge is deterministic; semantic contradiction detection is emitted as normal knowledge, not part of merge.
- Session graphs are first-class via `sess` on packets.

## Run

```bash
cargo test
cargo run --example two_node_demo
```

## Next

1. Replace in-memory `GraphState` with SparrowDB `GraphRepository`.
2. Add NATS/QUIC relay.
3. Add durable WAL via `redb` or RocksDB.
4. Add epoch range prover behind the `proof` interface.
