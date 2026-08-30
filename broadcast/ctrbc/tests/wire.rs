//! The CTRBC broadcast path, driven end to end without a network.
//!
//! Covers what the switch to commonware actually changed: shards and
//! commitments now travel as `commonware_codec` bytes inside the repository's
//! `bincode` messages, verification is a commitment check at a fixed index
//! rather than a Merkle proof against a locally rebuilt tree, and
//! reconstruction re-derives the commitment instead of comparing roots.

use ctrbc::{CTRBCMsg, ProtMsg};

/// `n = 3f + 1`, `k = n - 2f` data shards, `2f` parity.
fn params(n: usize) -> (usize, usize, usize) {
    let f = (n - 1) / 3;
    (f, n - 2 * f, 2 * f)
}

/// Serialize a message the way `WrapperMsg` does, then read it back.
fn round_trip(msg: &ProtMsg) -> ProtMsg {
    let bytes = bincode::serialize(msg).expect("serialize");
    bincode::deserialize(&bytes).expect("deserialize")
}

fn shard_of(msg: &ProtMsg) -> &CTRBCMsg {
    match msg {
        ProtMsg::Init(shard, _) | ProtMsg::Echo(shard, _) | ProtMsg::Ready(shard, _) => shard,
    }
}

#[test]
fn a_broadcast_survives_the_wire_and_reconstructs_from_n_minus_f_echos() {
    for n in [4usize, 7, 16, 64] {
        let (f, k, m) = params(n);
        let message: Vec<u8> = (0..9000u32).map(|i| (i % 241) as u8).collect();

        // Dealer: one INIT per node, each carrying that node's own shard.
        let (commitment, shards) = consensus::encode(&message, k, m).expect("encode");
        assert_eq!(shards.len(), n);

        let inits: Vec<ProtMsg> = (0..n)
            .map(|replica| {
                ProtMsg::Init(
                    CTRBCMsg {
                        shard: shards[replica].clone(),
                        commitment,
                        origin: 0,
                    },
                    7,
                )
            })
            .collect();

        // Each node receives its INIT off the wire and verifies it at its own
        // index, then echoes the same fragment.
        let mut echoes = Vec::new();
        for (replica, init) in inits.iter().enumerate() {
            let received = round_trip(init);
            let received = shard_of(&received);
            let checked = received
                .verify(replica, n, f)
                .unwrap_or_else(|| panic!("node {} rejected its own INIT at n={}", replica, n));
            echoes.push((replica, received.clone(), checked));
        }

        // A node collects n-f ECHOs. Drop the first f to stand in for the
        // faulty nodes that never send one.
        let survivors: Vec<_> = echoes.iter().skip(f).collect();
        assert_eq!(survivors.len(), n - f);

        let checked: Vec<_> = survivors.iter().map(|(_, _, c)| c.clone()).collect();
        let (decoded, regenerated) =
            consensus::decode_with_shards(&commitment, checked.iter(), k, m).expect("decode");

        assert_eq!(decoded, message, "n={}", n);
        // Reconstruction hands back every shard, so a node that never received
        // its own can still forward it in READY.
        assert_eq!(regenerated, shards, "n={}", n);
    }
}

#[test]
fn a_shard_replayed_at_another_index_is_rejected() {
    let n = 16;
    let (f, k, m) = params(n);
    let (commitment, shards) = consensus::encode(b"a broadcast payload", k, m).expect("encode");

    let msg = CTRBCMsg {
        shard: shards[5].clone(),
        commitment,
        origin: 0,
    };
    let msg = match round_trip(&ProtMsg::Echo(msg, 1)) {
        ProtMsg::Echo(msg, _) => msg,
        _ => unreachable!(),
    };

    assert!(msg.verify(5, n, f).is_some(), "shard 5 must verify at index 5");
    for other in [0usize, 4, 6, n - 1] {
        assert!(
            msg.verify(other, n, f).is_none(),
            "shard 5 must not verify at index {}",
            other
        );
    }
}

#[test]
fn a_shard_from_a_different_broadcast_is_rejected() {
    let n = 16;
    let (f, k, m) = params(n);
    let (commitment, _) = consensus::encode(b"the broadcast we committed to", k, m).unwrap();
    let (_, impostor) = consensus::encode(b"some other broadcast entirely", k, m).unwrap();

    let msg = CTRBCMsg {
        shard: impostor[3].clone(),
        commitment,
        origin: 0,
    };
    assert!(msg.verify(3, n, f).is_none());
}
