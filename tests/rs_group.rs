//! Reed–Solomon group encode/repair.

use lurpax::recovery::fec::{encode_rs_group, repair_group};

#[test]
fn rs_single_parity_shard_damage() {
    let shard_len = 64usize;
    let data: Vec<Vec<u8>> = (0..3)
        .map(|i| vec![i as u8; shard_len])
        .collect();
    let mut group = encode_rs_group(&data, 2).unwrap();
    assert_eq!(group.len(), 5);
    group[1] = vec![0xff; shard_len];
    let damaged = vec![false, true, false, false, false];
    repair_group(&mut group, 3, 2, &damaged).unwrap();
    assert_eq!(group[1], vec![1u8; shard_len]);
}
