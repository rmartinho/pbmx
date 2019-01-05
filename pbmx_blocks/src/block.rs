//! PBMX chain blocks

use digest::Digest;
use pbmx_crypto::{
    error::Error,
    group::Group,
    hash::Hash,
    keys::{Fingerprint, PrivateKey, PublicKey},
    vtmf::{Mask, MaskProof, PrivateMaskProof, SecretShare, SecretShareProof, ShuffleProof},
};
use pbmx_util::{
    derive_base64_conversions,
    serde::{serialize_flat_map, ToBytes},
};
use rug::{integer::Order, Integer};
use serde::de::{Deserialize, Deserializer};
use std::{
    collections::HashMap,
    fmt::{self, Display, Formatter},
    slice,
    str::{self, FromStr},
};

/// A block in a PBMX chain
#[derive(Clone, Debug, Serialize)]
pub struct Block {
    pub(super) acks: Vec<Id>,
    #[serde(serialize_with = "serialize_flat_map")]
    pub(super) payloads: HashMap<Id, Payload>,
    payload_order: Vec<Id>,
    fp: Fingerprint,
    sig: Signature,
}

impl Block {
    fn new(
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

    /// Checks whether this block's signature is valid
    pub fn valid(&self, pk: &PublicKey) -> bool {
        assert!(pk.fingerprint() == self.fp);

        let m = block_signature_hash(self.acks.iter(), self.payloads(), &self.fp);
        pk.verify(&m, &self.sig)
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
        h = h.chain(&ack.0);
    }
    for payload in payloads {
        println!("hashing {}", payload.id());
        h = h.chain(&payload.id().0);
    }
    h = h.chain(&fp.0);
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
        Block::new(
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
    ProveShuffle(Id, Id, Box<ShuffleProof>),
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

derive_base64_conversions!(Payload, Error);

/// A block or payload ID
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Id([u8; ID_SIZE]);

const ID_SIZE: usize = 20;

impl Display for Id {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        for b in self.0.iter() {
            write!(f, "{:02X}", b)?;
        }
        Ok(())
    }
}

impl FromStr for Id {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes: Vec<_> = s
            .as_bytes()
            .chunks(2)
            .map(|c| u8::from_str_radix(str::from_utf8(c).unwrap(), 16))
            .collect::<Result<_, _>>()?;
        if bytes.len() != ID_SIZE {
            return Err(Error::Hex(None));
        }
        let mut id = Id([0; ID_SIZE]);
        id.0.copy_from_slice(&bytes);
        Ok(id)
    }
}

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
pub type Signature = (Integer, Integer);

#[cfg(test)]
mod test {
    use super::{BlockBuilder, Payload};
    use pbmx_crypto::{group::Groups, keys::Keys};
    use rand::{thread_rng, Rng};

    #[test]
    fn new_block_has_valid_signature() {
        let mut rng = thread_rng();
        let dist = Groups {
            field_bits: 16,
            group_bits: 8,
            iterations: 64,
        };
        let group = rng.sample(&dist);
        let (sk, pk) = rng.sample(&Keys(&group));
        let block = BlockBuilder::new().build(&sk);

        assert!(block.valid(&pk));
    }

    #[test]
    fn block_payload_order_is_preserved() {
        let mut rng = thread_rng();
        let dist = Groups {
            field_bits: 16,
            group_bits: 8,
            iterations: 64,
        };
        let group = rng.sample(&dist);
        let (sk, pk) = rng.sample(&Keys(&group));
        let mut builder = BlockBuilder::new();
        builder.add_payload(Payload::Bytes(vec![0]));
        builder.add_payload(Payload::Bytes(vec![1]));
        builder.add_payload(Payload::Bytes(vec![2]));
        builder.add_payload(Payload::Bytes(vec![3]));
        let block = builder.build(&sk);

        println!("---");
        assert!(block.valid(&pk));

        let payloads: Vec<_> = block.payloads().cloned().collect();
        let expected: Vec<_> = [0u8, 1, 2, 3]
            .iter()
            .map(|&i| Payload::Bytes(vec![i]))
            .collect();
        assert_eq!(payloads, expected);
    }
}
