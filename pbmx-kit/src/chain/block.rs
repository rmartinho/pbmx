//! PBMX chain blocks

use crate::{
    chain::{
        payload::{Payload, PayloadVisitor},
        Id,
    },
    crypto::keys::{Fingerprint, HasFingerprint, PrivateKey, PublicKey},
    proto,
    serde::{vec_from_proto, vec_to_proto, Proto},
    Error,
};
use digest::generic_array::typenum::U32;
use merlin::Transcript;
use schnorrkel::Signature;
use std::{collections::HashMap, convert::TryFrom, slice};
use tribool::Tribool;

/// A block in a PBMX chain
#[derive(Clone, Debug)]
pub struct Block {
    acks: Vec<Id>,
    payloads: HashMap<Id, Payload>,
    payload_order: Vec<Id>,
    fp: Fingerprint,
    sig: Signature,
}

impl Proto for Vec<Payload> {
    type Message = proto::PayloadList;

    fn to_proto(&self) -> Result<Self::Message, Error> {
        Ok(proto::PayloadList {
            payloads: self
                .iter()
                .map(|p| p.to_proto())
                .collect::<Result<_, _>>()?,
        })
    }

    fn from_proto(m: &Self::Message) -> Result<Self, Error> {
        m.payloads.iter().map(|p| Payload::from_proto(&p)).collect()
    }
}

create_hash! {
    /// The hash used for block IDs
    struct BlockHash(Hash<U32>) = b"pbmx-block-id";
}

impl HasFingerprint for Block {
    type Digest = BlockHash;
}

impl Block {
    fn new_unchecked(
        acks: Vec<Id>,
        payloads: Vec<Payload>,
        fp: Fingerprint,
        sig: Signature,
    ) -> Block {
        let payload_order = payloads.iter().map(|p| p.id()).collect();
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
        self.fingerprint().unwrap()
    }

    /// Gets the fingerprint of the block's signing key
    pub fn signer(&self) -> Fingerprint {
        self.fp
    }

    /// Checks whether this block's signature is valid
    pub fn is_valid(&self, pk: &HashMap<Fingerprint, PublicKey>) -> Tribool {
        pk.get(&self.fp).map_or(Tribool::Indeterminate, |pk| {
            let mut t = block_signing_context(self.acks.iter(), self.payloads(), &self.fp);
            pk.verify(&mut t, &self.sig).is_ok().into()
        })
    }

    /// Gets this block's parent IDs
    pub fn parent_ids(&self) -> &[Id] {
        &self.acks
    }

    /// Gets this block's payloads in order
    pub fn payloads(&self) -> impl ExactSizeIterator<Item = &Payload> {
        PayloadIter {
            payload_order: self.payload_order.iter(),
            payloads: &self.payloads,
        }
    }

    /// Visits this block
    pub fn visit<V: BlockVisitor>(&self, v: &mut V) {
        v.visit_block(self);
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
        self.payloads.get(id)
    }
}

impl<'a> ExactSizeIterator for PayloadIter<'a> {
    fn len(&self) -> usize {
        self.payloads.len()
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
        let mut t = block_signing_context(self.acks.iter(), self.payloads.iter(), &fp);
        let sig = sk.sign(&mut t);
        Block {
            acks: self.acks,
            payload_order: self.payloads.iter().map(Payload::id).collect(),
            payloads: self.payloads.into_iter().map(|p| (p.id(), p)).collect(),
            fp,
            sig,
        }
    }
}

fn block_signing_context<'a, AckIt, PayloadIt>(
    acks: AckIt,
    payloads: PayloadIt,
    fp: &Fingerprint,
) -> Transcript
where
    AckIt: Iterator<Item = &'a Id> + 'a,
    PayloadIt: Iterator<Item = &'a Payload> + 'a,
{
    let mut t = Transcript::new(b"pbmx-block");
    for ack in acks {
        t.append_message(b"ack", &ack);
    }
    for payload in payloads {
        t.append_message(b"payload", &payload.id());
    }
    t.append_message(b"signer", &fp);
    t
}

struct BlockRaw {
    acks: Vec<Id>,
    payloads: Vec<Payload>,
    fp: Fingerprint,
    sig: Signature,
}

impl BlockRaw {
    fn from(b: &Block) -> Self {
        Self {
            acks: b.acks.clone(),
            payloads: b
                .payload_order
                .iter()
                .map(|id| b.payloads[id].clone())
                .collect(),
            fp: b.fp,
            sig: b.sig,
        }
    }

    fn into(self) -> Block {
        Block::new_unchecked(self.acks, self.payloads, self.fp, self.sig)
    }
}

impl Proto for BlockRaw {
    type Message = proto::Block;

    fn to_proto(&self) -> Result<proto::Block, Error> {
        Ok(proto::Block {
            acks: self.acks.iter().map(|id| id.to_vec()).collect(),
            payloads: vec_to_proto(&self.payloads)?,
            fingerprint: self.fp.to_vec(),
            signature: self.sig.to_bytes().to_vec(),
        })
    }

    fn from_proto(m: &proto::Block) -> Result<Self, Error> {
        Ok(Self {
            acks: m
                .acks
                .iter()
                .map(|b| Id::try_from(b))
                .collect::<Result<_, _>>()?,
            payloads: vec_from_proto(&m.payloads)?,
            fp: Fingerprint::try_from(&m.fingerprint)?,
            sig: Signature::from_bytes(&m.signature).map_err(|_| Error::Decoding)?,
        })
    }
}

impl Proto for Block {
    type Message = proto::Block;

    fn to_proto(&self) -> Result<proto::Block, Error> {
        BlockRaw::from(self).to_proto()
    }

    fn from_proto(m: &proto::Block) -> Result<Self, Error> {
        Ok(BlockRaw::from_proto(m)?.into())
    }
}

/// A visitor for blocks
pub trait BlockVisitor: PayloadVisitor {
    /// Visits a block
    fn visit_block(&mut self, block: &Block) {
        for payload in block.payloads() {
            self.visit_payload(block, payload);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Block, BlockBuilder};
    use crate::{
        chain::payload::Payload,
        crypto::keys::PrivateKey,
        serde::{FromBase64, ToBase64},
    };
    use rand::thread_rng;
    use std::collections::HashMap;

    #[test]
    fn new_block_has_valid_signature() {
        let mut rng = thread_rng();
        let sk = PrivateKey::random(&mut rng);
        let pk = sk.public_key();
        let ring: HashMap<_, _> = vec![pk].into_iter().map(|k| (k.fingerprint(), k)).collect();

        let block = BlockBuilder::new().build(&sk);

        assert!(block.is_valid(&ring).is_true());
    }

    #[test]
    fn block_payload_order_is_preserved() {
        let mut rng = thread_rng();
        let sk = PrivateKey::random(&mut rng);
        let pk = sk.public_key();
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
        let sk = PrivateKey::random(&mut rng);
        let pk = sk.public_key();
        let ring: HashMap<_, _> = vec![pk].into_iter().map(|k| (k.fingerprint(), k)).collect();
        let mut builder = BlockBuilder::new();
        builder.add_payload(Payload::Bytes(vec![0]));
        builder.add_payload(Payload::Bytes(vec![1]));
        builder.add_payload(Payload::Bytes(vec![2]));
        builder.add_payload(Payload::Bytes(vec![3]));
        let original = builder.build(&sk);

        let exported = original.to_base64().unwrap();

        let recovered = Block::from_base64(&exported).unwrap();
        assert!(recovered.is_valid(&ring).is_true());

        assert_eq!(original.acks, recovered.acks);
        assert_eq!(original.payloads, recovered.payloads);
        assert_eq!(original.payload_order, recovered.payload_order);
        assert_eq!(original.fp, recovered.fp);
        assert_eq!(original.sig, recovered.sig);
    }
}
