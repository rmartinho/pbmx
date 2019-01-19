//! PBMX chain blocks

use crate::error::Error;
use digest::Digest;
use pbmx_crypto::{
    hash::Hash,
    keys::{Fingerprint, PrivateKey, PublicKey},
    schnorr::SchnorrGroup,
    vtmf::{Mask, MaskProof, PrivateMaskProof, SecretShare, SecretShareProof, ShuffleProof},
};
use pbmx_serde::{derive_base64_conversions, serialize_flat_map};
use rug::{integer::Order, Integer};
use serde::de::{Deserialize, Deserializer};
use std::{collections::HashMap, slice, str};
use tribool::Tribool;

/// A block in a PBMX chain
#[derive(Clone, Debug, Serialize)]
pub struct Block {
    acks: Vec<Id>,
    #[serde(serialize_with = "serialize_flat_map")]
    payloads: HashMap<Id, Payload>,
    payload_order: Vec<Id>,
    fp: Fingerprint,
    sig: Signature,
}

impl Block {
    fn new_unchecked(
        acks: Vec<Id>,
        payloads: Vec<Payload>,
        payload_order: Vec<Id>,
        fp: Fingerprint,
        sig: Signature,
    ) -> Block {
        Block {
            acks,
            sig,
            fp,
            payload_order,
            payloads: payloads.into_iter().map(|p| (p.id(), p)).collect(),
        }
    }

    /// Gets this block's ID
    pub fn id(&self) -> Id {
        Id::of(self).unwrap()
    }

    /// Gets the fingerprint of the block's signing key
    pub fn signer(&self) -> Fingerprint {
        self.fp
    }

    /// Checks whether this block's signature is valid
    pub fn is_valid(&self, pk: &HashMap<Fingerprint, PublicKey>) -> Tribool {
        let m = block_signature_hash(self.acks.iter(), self.payloads(), &self.fp);
        pk.get(&self.fp)
            .map_or(Tribool::Indeterminate, |pk| pk.verify(&m, &self.sig).into())
    }

    /// Gets this block's parent IDs
    pub fn parent_ids(&self) -> &[Id] {
        &self.acks
    }

    /// Gets this block's payloads in order
    pub fn payloads(&self) -> impl Iterator<Item = &Payload> {
        PayloadIter {
            payload_order: self.payload_order.iter(),
            payloads: &self.payloads,
        }
    }
}

struct PayloadIter<'a> {
    payload_order: slice::Iter<'a, Id>,
    payloads: &'a HashMap<Id, Payload>,
}

impl<'a> Iterator for PayloadIter<'a> {
    type Item = &'a Payload;

    fn next(&mut self) -> Option<Self::Item> {
        let id = self.payload_order.next()?;
        self.payloads.get(&id)
    }
}

/// A builder for blocks
#[derive(Default)]
pub struct BlockBuilder {
    acks: Vec<Id>,
    payloads: Vec<Payload>,
}

impl BlockBuilder {
    /// Creates a new, empty, block builder
    pub fn new() -> BlockBuilder {
        BlockBuilder::default()
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
    pub fn build(self, sk: &PrivateKey) -> Block {
        let fp = sk.fingerprint();
        let m = block_signature_hash(self.acks.iter(), self.payloads.iter(), &fp);
        let sig = sk.sign(&m);
        Block {
            acks: self.acks,
            payload_order: self.payloads.iter().map(|p| p.id()).collect(),
            payloads: self.payloads.into_iter().map(|p| (p.id(), p)).collect(),
            fp,
            sig,
        }
    }
}

fn block_signature_hash<'a, AckIt, PayloadIt>(
    acks: AckIt,
    payloads: PayloadIt,
    fp: &Fingerprint,
) -> Integer
where
    AckIt: Iterator<Item = &'a Id> + 'a,
    PayloadIt: Iterator<Item = &'a Payload> + 'a,
{
    let mut h = Hash::new();
    for ack in acks {
        h = h.chain(&ack);
    }
    for payload in payloads {
        h = h.chain(&payload.id());
    }
    h = h.chain(&fp);
    Integer::from_digits(&h.result(), Order::MsfBe)
}

impl<'de> Deserialize<'de> for Block {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(BlockRaw::deserialize(deserializer)?.into())
    }
}

#[derive(Deserialize)]
struct BlockRaw {
    acks: Vec<Id>,
    payloads: Vec<Payload>,
    payload_order: Vec<Id>,
    fp: Fingerprint,
    sig: Signature,
}

impl BlockRaw {
    fn into(self) -> Block {
        Block::new_unchecked(
            self.acks,
            self.payloads,
            self.payload_order,
            self.fp,
            self.sig,
        )
    }
}

derive_base64_conversions!(Block, Error);

/// A PBMX message payload
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Payload {
    /// A game definition payload
    DefineGame(String, SchnorrGroup),
    /// A public key payload
    PublishKey(PublicKey),
    /// An open stack payload
    OpenStack(Vec<Mask>),
    /// A private stack payload
    PrivateStack(Id, Vec<Mask>, Vec<PrivateMaskProof>),
    /// A stack name payload
    NameStack(Id, String),
    /// A stack mask payload
    MaskStack(Id, Vec<Mask>, Vec<MaskProof>),
    /// A stack shuffle payload
    ShuffleStack(Id, Vec<Mask>, ShuffleProof),
    // /// A stack shift payload
    // ShiftStack(Id, Vec<Mask>, ShiftProof),
    /// A secret share payload
    PublishShares(Id, Vec<SecretShare>, Vec<SecretShareProof>),
    /// A random bound payload
    StartRandom(Integer),
    /// A random share payload
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

derive_base64_conversions!(Payload, Error);

/// A block or payload ID
pub type Id = Fingerprint;

/// A block signature
pub type Signature = (Integer, Integer);

#[cfg(test)]
mod test {
    use super::{Block, BlockBuilder, Payload};
    use pbmx_crypto::{keys::Keys, schnorr::SchnorrGroups};
    use rand::{thread_rng, Rng};
    use std::{collections::HashMap, str::FromStr};

    #[test]
    fn new_block_has_valid_signature() {
        let mut rng = thread_rng();
        let dist = SchnorrGroups {
            field_bits: 16,
            group_bits: 8,
            iterations: 64,
        };
        let group = rng.sample(&dist);
        let (sk, pk) = rng.sample(&Keys(&group));
        let ring: HashMap<_, _> = vec![pk].into_iter().map(|k| (k.fingerprint(), k)).collect();
        let block = BlockBuilder::new().build(&sk);

        assert!(block.is_valid(&ring).is_true());
    }

    #[test]
    fn block_payload_order_is_preserved() {
        let mut rng = thread_rng();
        let dist = SchnorrGroups {
            field_bits: 16,
            group_bits: 8,
            iterations: 64,
        };
        let group = rng.sample(&dist);
        let (sk, pk) = rng.sample(&Keys(&group));
        let ring: HashMap<_, _> = vec![pk].into_iter().map(|k| (k.fingerprint(), k)).collect();
        let mut builder = BlockBuilder::new();
        builder.add_payload(Payload::Bytes(vec![0]));
        builder.add_payload(Payload::Bytes(vec![1]));
        builder.add_payload(Payload::Bytes(vec![2]));
        builder.add_payload(Payload::Bytes(vec![3]));
        let block = builder.build(&sk);

        assert!(block.is_valid(&ring).is_true());

        let payloads: Vec<_> = block.payloads().cloned().collect();
        let expected: Vec<_> = [0u8, 1, 2, 3]
            .iter()
            .map(|&i| Payload::Bytes(vec![i]))
            .collect();
        assert_eq!(payloads, expected);
    }

    #[test]
    fn block_roundtrips_via_base64() {
        let mut rng = thread_rng();
        let dist = SchnorrGroups {
            field_bits: 16,
            group_bits: 8,
            iterations: 64,
        };
        let group = rng.sample(&dist);
        let (sk, pk) = rng.sample(&Keys(&group));
        let ring: HashMap<_, _> = vec![pk].into_iter().map(|k| (k.fingerprint(), k)).collect();
        let mut builder = BlockBuilder::new();
        builder.add_payload(Payload::Bytes(vec![0]));
        builder.add_payload(Payload::Bytes(vec![1]));
        builder.add_payload(Payload::Bytes(vec![2]));
        builder.add_payload(Payload::Bytes(vec![3]));
        let original = builder.build(&sk);
        println!("block = {}", original);

        let exported = original.to_string();

        let recovered = Block::from_str(&exported).unwrap();
        assert!(recovered.is_valid(&ring).is_true());

        assert_eq!(original.acks, recovered.acks);
        assert_eq!(original.payloads, recovered.payloads);
        assert_eq!(original.payload_order, recovered.payload_order);
        assert_eq!(original.fp, recovered.fp);
        assert_eq!(original.sig, recovered.sig);
    }
}
