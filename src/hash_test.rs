use crate::hash::{pedersen_hash, pedersen_hash_array};
use crate::transaction::Fee;
use num_traits::cast::ToPrimitive;
use starknet_types_core::felt::Felt;

#[test]
fn pedersen_hash_correctness() {
    // Test vectors from https://github.com/starkware-libs/crypto-cpp/blob/master/src/starkware/crypto/pedersen_hash_test.cc
    let a = Felt::from_hex("0x03d937c035c878245caf64531a5756109c53068da139362728feb561405371cb")
        .unwrap();
    let b = Felt::from_hex("0x0208a0a10250e382e1e4bbe2880906c2791bf6275695e02fbbc6aeff9cd8b31a")
        .unwrap();
    let expected =
        Felt::from_hex("0x030e480bed5fe53fa909cc0f8c4d99b8f9f2c016be4c41e13a4848797979c662")
            .unwrap();
    assert_eq!(pedersen_hash(&a, &b), expected);
}

#[test]
fn pedersen_hash_array_correctness() {
    let a = Felt::from_hex("0xaa").unwrap();
    let b = Felt::from_hex("0xbb").unwrap();
    let c = Felt::from_hex("0xcc").unwrap();
    let expected = pedersen_hash(
        &pedersen_hash(&pedersen_hash(&pedersen_hash(&Felt::from_hex("0x0").unwrap(), &a), &b), &c),
        &Felt::from_hex("0x3").unwrap(),
    );
    assert_eq!(pedersen_hash_array(&[a, b, c]), expected);
}

#[test]
fn felts_array_serde() {
    let felts = [
        Felt::from_hex("0x123").unwrap(),
        Felt::from_hex("0xabf").unwrap(),
        Felt::from_hex("0x24ba891239123").unwrap(),
        Felt::from_hex("0xffff").unwrap(),
    ];
    let serde_string = serde_json::to_string(&felts).unwrap();
    let deserilize: [Felt; 4] = serde_json::from_str(&serde_string).unwrap();
    assert_eq!(felts, deserilize);
}

#[test]
fn hash_macro() {
    assert_eq!(
        Felt::from_hex("0x123").unwrap(),
        Felt::from_bytes_be(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0x1, 0x23
        ])
        .unwrap()
    );
}

#[test]
fn hash_json_serde() {
    let hash = Felt::from_hex("0x123").unwrap();
    assert_eq!(hash, serde_json::from_str(&serde_json::to_string(&hash).unwrap()).unwrap());
}

#[test]
fn felts_serde() {
    for n_nibbles in 0..64 {
        let mut bytes = [0u8; 32];
        // Set all nibbles to 0xf.
        for i in 0..n_nibbles {
            bytes[31 - (i >> 1)] |= 15 << (4 * (i & 1));
        }
        let felt: Felt = Felt::from_bytes_be(&bytes).unwrap();

        let serde = serde_json::to_vec(&felt).unwrap();

        let deserde: Felt = serde_json::from_slice(&serde).unwrap();
        assert_eq!(felt, deserde);
    }
}

#[test]
fn fee_to_starkfelt() {
    let fee = Fee(u128::MAX);
    assert_eq!(format!("{:#x}", Felt::from(fee)), format!("{:#x}", fee.0));
}

#[test]
fn felt_to_u64_and_back() {
    // Positive flow.
    let value = u64::MAX;
    let felt = Felt::from(value);
    let new_value = felt.to_u64();
    assert_eq!(Some(value), new_value);

    // Negative flow.
    let value: u128 = u128::from(u64::MAX) + 1;
    let another_felt: Felt = value.into();
    assert_eq!(another_felt.to_u64(), None);
}
