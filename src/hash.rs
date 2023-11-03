#[cfg(test)]
#[path = "hash_test.rs"]
mod hash_test;

use starknet_types_core::felt::Felt;
//TODO, change alias TypeRsPedersen
use starknet_types_core::hash::Pedersen as TypeRsPedersen;
use starknet_types_core::hash::StarkHash as Sh;

/// Genesis state hash.
pub const GENESIS_HASH: &str = "0x0";

// Felt encoding constants.
// const CHOOSER_FULL: u8 = 15;
// const CHOOSER_HALF: u8 = 14;

/// An alias for [`StarkFelt`].
/// The output of the [Pedersen hash](https://docs.starknet.io/documentation/architecture_and_concepts/Hashing/hash-functions/#pedersen_hash).
pub type StarkHash = Felt;

/// Computes Pedersen hash using STARK curve on two elements, as defined
/// in <https://docs.starknet.io/documentation/architecture_and_concepts/Hashing/hash-functions/#pedersen_hash.>
pub fn pedersen_hash(felt0: &Felt, felt1: &Felt) -> StarkHash {
    TypeRsPedersen::hash(felt0, felt1)
}

/// Computes Pedersen hash using STARK curve on an array of elements, as defined
/// in <https://docs.starknet.io/documentation/architecture_and_concepts/Hashing/hash-functions/#array_hashing.>
pub fn pedersen_hash_array(felts: &[Felt]) -> StarkHash {
    TypeRsPedersen::hash_array(felts)
}
