#[cfg(test)]
#[path = "core_test.rs"]
mod core_test;

use std::fmt::Debug;

use derive_more::Display;
use once_cell::sync::Lazy;
use primitive_types::H160;
use serde::{Deserialize, Serialize};
use starknet_types_core::felt::{Felt, NonZeroFelt};
use starknet_types_core::hash::{Pedersen, StarkHash as Sh};

use crate::hash::{pedersen_hash_array, StarkHash};
use crate::serde_utils::{BytesAsHex, PrefixedBytesAsHex};
use crate::transaction::{Calldata, ContractAddressSalt};
use crate::{impl_from_through_intermediate, StarknetApiError};

/// A chain id.
#[derive(Clone, Debug, Display, Eq, PartialEq, Hash, Deserialize, Serialize, PartialOrd, Ord)]
pub struct ChainId(pub String);

impl ChainId {
    pub fn as_hex(&self) -> String {
        format!("0x{}", hex::encode(&self.0))
    }
}

/// The address of a contract, used for example in [StateDiff](`crate::state::StateDiff`),
/// [DeclareTransaction](`crate::transaction::DeclareTransaction`), and
/// [BlockHeader](`crate::block::BlockHeader`).

// The block hash table is stored in address 0x1,
// this is a special address that is not used for contracts.
pub const BLOCK_HASH_TABLE_ADDRESS: ContractAddress = ContractAddress(PatriciaKey(StarkHash::ONE));
#[derive(
    Debug, Default, Copy, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, PartialOrd, Ord,
)]
pub struct ContractAddress(pub PatriciaKey);

impl From<u128> for ContractAddress {
    fn from(val: u128) -> Self {
        ContractAddress(PatriciaKey::from(val))
    }
}

impl_from_through_intermediate!(u128, ContractAddress, u8, u16, u32, u64);

/// The maximal size of storage var.
pub const MAX_STORAGE_ITEM_SIZE: u16 = 256;
/// The prefix used in the calculation of a contract address.
pub const CONTRACT_ADDRESS_PREFIX: &str = "STARKNET_CONTRACT_ADDRESS";
/// The size of the contract address domain.
pub static CONTRACT_ADDRESS_PREFIX_FELT: Lazy<Felt> = Lazy::new(|| {
    Felt::from_hex(format!("0x{}", hex::encode(CONTRACT_ADDRESS_PREFIX)).as_str()).unwrap()
});
pub static CONTRACT_ADDRESS_DOMAIN_SIZE: Lazy<Felt> = Lazy::new(|| {
    Felt::from_hex(PATRICIA_KEY_UPPER_BOUND)
        .unwrap_or_else(|_| panic!("Failed to convert {PATRICIA_KEY_UPPER_BOUND} to Felt"))
});
/// The address upper bound; it is defined to be congruent with the storage var address upper bound.
pub static L2_ADDRESS_UPPER_BOUND: Lazy<NonZeroFelt> = Lazy::new(|| {
    ((*CONTRACT_ADDRESS_DOMAIN_SIZE) - Felt::from(MAX_STORAGE_ITEM_SIZE)).try_into().unwrap()
});

impl TryFrom<StarkHash> for ContractAddress {
    type Error = StarknetApiError;
    fn try_from(hash: StarkHash) -> Result<Self, Self::Error> {
        Ok(Self(PatriciaKey::try_from(hash)?))
    }
}

// TODO: Add a hash_function as a parameter
pub fn calculate_contract_address(
    salt: ContractAddressSalt,
    class_hash: ClassHash,
    constructor_calldata: &Calldata,
    deployer_address: ContractAddress,
) -> Result<ContractAddress, StarknetApiError> {
    let constructor_calldata_hash = pedersen_hash_array(&constructor_calldata.0);
    let mut address = Pedersen::hash_array(&[
        *CONTRACT_ADDRESS_PREFIX_FELT,
        *deployer_address.0.key(),
        salt.0,
        class_hash.0,
        constructor_calldata_hash,
    ]);
    address = address.mod_floor(&L2_ADDRESS_UPPER_BOUND);

    ContractAddress::try_from(address)
}

/// The hash of a ContractClass.
#[derive(
    Debug,
    Default,
    Copy,
    Clone,
    Eq,
    PartialEq,
    Hash,
    Deserialize,
    Serialize,
    PartialOrd,
    Ord,
    Display,
)]
pub struct ClassHash(pub StarkHash);

/// The hash of a compiled ContractClass.
#[derive(
    Debug,
    Default,
    Copy,
    Clone,
    Eq,
    PartialEq,
    Hash,
    Deserialize,
    Serialize,
    PartialOrd,
    Ord,
    Display,
)]
pub struct CompiledClassHash(pub StarkHash);

/// A general type for nonces.
#[derive(
    Debug,
    Default,
    Copy,
    Clone,
    Eq,
    PartialEq,
    Hash,
    Deserialize,
    Serialize,
    PartialOrd,
    Ord,
    derive_more::Deref,
)]
pub struct Nonce(pub Felt);

impl Nonce {
    pub fn try_increment(&self) -> Result<Self, StarknetApiError> {
        let incremented_felt = self.0 + Felt::ONE;

        // Check if an overflow occurred during increment.
        if incremented_felt == Felt::ZERO {
            return Err(StarknetApiError::OutOfRange { string: format!("{:?}", self) });
        };

        Ok(Nonce(incremented_felt))
    }
}

/// The selector of an [EntryPoint](`crate::deprecated_contract_class::EntryPoint`).
#[derive(
    Debug, Copy, Clone, Default, Eq, PartialEq, Hash, Deserialize, Serialize, PartialOrd, Ord,
)]
pub struct EntryPointSelector(pub StarkHash);

/// The root of the global state at a [Block](`crate::block::Block`)
/// and [StateUpdate](`crate::state::StateUpdate`).
#[derive(
    Debug,
    Copy,
    Clone,
    Default,
    Eq,
    PartialEq,
    Hash,
    Deserialize,
    Serialize,
    PartialOrd,
    Ord,
    Display,
)]
pub struct GlobalRoot(pub StarkHash);

/// A key for nodes of a Patricia tree.
// Invariant: key is in range.
#[derive(Copy, Clone, Eq, PartialEq, Default, Hash, Deserialize, Serialize, PartialOrd, Ord)]
pub struct PatriciaKey(StarkHash);

// 2**251
pub const PATRICIA_KEY_UPPER_BOUND: &str =
    "0x800000000000000000000000000000000000000000000000000000000000000";

impl PatriciaKey {
    pub fn key(&self) -> &StarkHash {
        &self.0
    }
}

impl From<u128> for PatriciaKey {
    fn from(val: u128) -> Self {
        PatriciaKey::try_from(Felt::from(val)).expect("Failed to convert u128 to PatriciaKey.")
    }
}

impl_from_through_intermediate!(u128, PatriciaKey, u8, u16, u32, u64);

impl TryFrom<StarkHash> for PatriciaKey {
    type Error = StarknetApiError;

    fn try_from(value: StarkHash) -> Result<Self, Self::Error> {
        if value < *CONTRACT_ADDRESS_DOMAIN_SIZE {
            return Ok(PatriciaKey(value));
        }
        Err(StarknetApiError::OutOfRange { string: format!("[0x0, {PATRICIA_KEY_UPPER_BOUND})") })
    }
}

impl Debug for PatriciaKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PatriciaKey").field(&self.0).finish()
    }
}

/// A utility macro to create a [`ContractAddress`] from a hex string / unsigned integer
/// representation.
#[cfg(any(feature = "testing", test))]
#[macro_export]
macro_rules! contract_address {
    ($s:expr) => {
        ContractAddress(patricia_key!($s))
    };
}

/// An Ethereum address.
#[derive(
    Debug, Copy, Clone, Default, Eq, PartialEq, Hash, Deserialize, Serialize, PartialOrd, Ord,
)]
#[serde(try_from = "PrefixedBytesAsHex<20_usize>", into = "PrefixedBytesAsHex<20_usize>")]
pub struct EthAddress(pub H160);

impl TryFrom<Felt> for EthAddress {
    type Error = StarknetApiError;
    fn try_from(felt: Felt) -> Result<Self, Self::Error> {
        const COMPLIMENT_OF_H160: usize = std::mem::size_of::<Felt>() - H160::len_bytes();

        let binding = felt.to_bytes_be();
        let (rest, h160_bytes) = binding.split_at(COMPLIMENT_OF_H160);

        if rest != [0u8; COMPLIMENT_OF_H160] {
            return Err(StarknetApiError::OutOfRange { string: felt.to_string() });
        }

        Ok(EthAddress(H160::from_slice(h160_bytes)))
    }
}

impl TryFrom<PrefixedBytesAsHex<20_usize>> for EthAddress {
    type Error = StarknetApiError;
    fn try_from(val: PrefixedBytesAsHex<20_usize>) -> Result<Self, Self::Error> {
        Ok(EthAddress(H160::from_slice(&val.0)))
    }
}

impl From<EthAddress> for PrefixedBytesAsHex<20_usize> {
    fn from(felt: EthAddress) -> Self {
        BytesAsHex(felt.0.to_fixed_bytes())
    }
}
