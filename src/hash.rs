#[cfg(test)]
#[path = "hash_test.rs"]
mod hash_test;

use starknet_types_core::felt::Felt;
use starknet_types_core::hash::Pedersen;
use starknet_types_core::hash::StarkHash as Sh;

/// Genesis state hash.
pub const GENESIS_HASH: &str = "0x0";

/// An alias for [`StarkFelt`].
/// The output of the [Pedersen hash](https://docs.starknet.io/documentation/architecture_and_concepts/Hashing/hash-functions/#pedersen_hash).
pub type StarkHash = Felt;

/// Computes Pedersen hash using STARK curve on two elements, as defined
/// in <https://docs.starknet.io/documentation/architecture_and_concepts/Hashing/hash-functions/#pedersen_hash.>
pub fn pedersen_hash(felt0: &Felt, felt1: &Felt) -> StarkHash {
    Pedersen::hash(felt0, felt1)
}

/// Computes Pedersen hash using STARK curve on an array of elements, as defined
/// in <https://docs.starknet.io/documentation/architecture_and_concepts/Hashing/hash-functions/#array_hashing.>
pub fn pedersen_hash_array(felts: &[Felt]) -> StarkHash {
    Pedersen::hash_array(felts)
}
