//! PBMX chain blocks

use digest::Digest;
use pbmx_crypto::{
    derive_base64_conversions,
    group::Group,
    hash::Hash,
    keys::{PrivateKey, PublicKey},
    serde::ToBytes,
    vtmf::{Mask, MaskProof, PrivateMaskProof, SecretShare, SecretShareProof, ShuffleProof},
};
use rug::Integer;
use std::collections::HashMap;

/// A block in a PBMX chain
#[derive(Serialize, Deserialize)]
pub struct Block {
    acks: Vec<Id>,
    payloads: HashMap<Id, Payload>,
    sig: Signature,
}

/// A builder for a block
pub struct BlockBuilder {
    acks: Vec<Id>,
    payloads: Vec<Payload>,
}

impl BlockBuilder {
    /// Creates a new, empty, block builder
    pub fn new() -> BlockBuilder {
        BlockBuilder {
            acks: Vec::new(),
            payloads: Vec::new(),
        }
    }

    /// Adds an acknowledgement to a previous block
    pub fn acknowledge(&mut self, id: Id) -> &mut BlockBuilder {
        self.acks.push(id);
        self
    }

    /// Adds a payload to the block
    pub fn add_payload(&mut self, payload: Payload) -> &mut BlockBuilder {
        self.payloads.push(payload);
        self
    }

    /// Builds the block, consuming the builder
    pub fn build(self, pk: &PrivateKey) -> Block {
        Block {
            acks: self.acks,
            payloads: self.payloads.into_iter().map(|p| (p.id(), p)).collect(),
            sig: Signature(Integer::new(), Integer::new()),
        }
    }
}

derive_base64_conversions!(Block);

/// A PBMX message payload
#[derive(Serialize, Deserialize)]
pub enum Payload {
    /// A game definition payload
    DefineGame(String),
    /// A group payload
    PublishGroup(Group),
    /// A public key payload
    PublishKey(PublicKey),
    /// A stack payload
    CreateStack(Vec<Mask>),
    /// A stack name payload
    NameStack(String, Id),
    /// A stack mask proof payload
    ProveMask(Id, Id, Vec<MaskProof>),
    /// A stack private mask proof payload
    ProvePrivateMask(Id, Id, Vec<PrivateMaskProof>),
    /// A stack shuffle proof payload
    ProveShuffle(Id, Id, ShuffleProof),
    // /// A stack shift proof payload
    // ProveShift(Id, Id, ShiftProof),
    /// A secret share payload
    PublishShares(Id, Vec<SecretShare>),
    /// A secret share proof payload
    ProveShares(Id, Vec<SecretShareProof>),
    /// A random generation start payload
    GenerateRandom(Integer),
    /// A random generation share payload
    RandomShare(Id, Mask),
    /// Raw byte payload
    Bytes(Vec<u8>),
}

impl Payload {
    /// Gets the id of this payload
    pub fn id(&self) -> Id {
        Id::of(self).unwrap()
    }
}

derive_base64_conversions!(Payload);

/// A block or payload ID
#[derive(PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Id([u8; 20]);

impl Id {
    fn of<T>(x: &T) -> Result<Id, T::Error>
    where
        T: ToBytes,
    {
        let bytes = x.to_bytes()?;
        let hashed = Hash::new().chain(bytes).result();
        let mut array = [0u8; 20];
        array.copy_from_slice(&hashed);
        Ok(Id(array))
    }
}

/// A block signature
#[derive(Serialize, Deserialize)]
pub struct Signature(Integer, Integer);
