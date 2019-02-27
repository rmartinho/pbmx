//! Block payloads

use crate::{
    chain::{block::Block, Id},
    crypto::{
        keys::PublicKey,
        vtmf::{
            InsertProof, Mask, MaskProof, SecretShare, SecretShareProof, ShiftProof, ShuffleProof,
            Stack,
        },
    },
};
use std::fmt::{self, Display, Formatter};

/// A PBMX message payload
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Payload {
    /// A public key payload
    PublishKey(String, PublicKey),
    /// An open stack payload
    OpenStack(Stack),
    /// A stack mask payload
    MaskStack(Id, Stack, Vec<MaskProof>),
    /// A stack shuffle payload
    ShuffleStack(Id, Stack, ShuffleProof),
    /// A stack shift payload
    ShiftStack(Id, Stack, ShiftProof),
    /// A stack name payload
    NameStack(Id, String),
    /// A substack payload
    TakeStack(Id, Vec<usize>, Id),
    /// A stack pile payload
    PileStacks(Vec<Id>, Id),
    /// A insert token payload
    InsertStack(Id, Id, Stack, InsertProof),
    /// A secret share payload
    PublishShares(Id, Vec<SecretShare>, Vec<SecretShareProof>),
    /// An rng specification payload
    RandomSpec(String, String),
    /// An rng entropy payload
    RandomEntropy(String, Mask),
    /// An rng reveal payload
    RandomReveal(String, SecretShare, SecretShareProof),
    /// Raw byte payload
    Bytes(Vec<u8>),
}

impl Payload {
    /// Gets the id of this payload
    pub fn id(&self) -> Id {
        Id::of(self).unwrap()
    }

    /// Gets a short string description of this payload
    pub fn display_short<'a>(&'a self) -> impl Display + 'a {
        DisplayShort(self)
    }
}

struct DisplayShort<'a>(&'a Payload);

impl<'a> Display for DisplayShort<'a> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        use Payload::*;
        match self.0 {
            PublishKey(name, pk) => write!(f, "publish key {} {:16}", name, pk.fingerprint()),
            OpenStack(stk) => write!(f, "open stack {:16}", stk.id()),
            NameStack(id, name) => write!(f, "name {:16} {}", id, name),
            MaskStack(id, stk, _) => write!(f, "mask {1:16} \u{21AC} {0:16}", id, stk.id()),
            ShuffleStack(id, stk, _) => write!(f, "shuffle {1:16} \u{224B} {0:16}", id, stk.id()),
            ShiftStack(id, stk, _) => write!(f, "cut {1:16} \u{21CB} {0:16}", id, stk.id()),
            TakeStack(id1, idxs, id2) => write!(f, "take {:16}{:?} {:16}", id1, idxs, id2),
            PileStacks(ids, id2) => write!(f, "pile {:16?} {:16}", ids, id2),
            InsertStack(id1, id2, stk, _) => {
                write!(f, "insert {:16} {:16} {:16}", id1, id2, stk.id())
            }
            PublishShares(id, ..) => write!(f, "reveal {:16}", id),
            RandomSpec(id, ..) => write!(f, "new rng {}", id),
            RandomEntropy(id, ..) => write!(f, "add entropy {}", id),
            RandomReveal(id, ..) => write!(f, "open rng {}", id),
            Bytes(bytes) => write!(f, "message {}", &String::from_utf8_lossy(bytes)),
        }
    }
}

derive_base64_conversions!(Payload);

/// A visitor for payloads
pub trait PayloadVisitor {
    /// Visits a payload
    fn visit_payload(&mut self, block: &Block, payload: &Payload) {
        use Payload::*;
        match payload {
            PublishKey(name, pk) => {
                self.visit_publish_key(block, name, pk);
            }
            OpenStack(stk) => {
                self.visit_open_stack(block, stk);
            }
            MaskStack(id, stk, proof) => {
                self.visit_mask_stack(block, *id, stk, proof);
            }
            ShuffleStack(id, stk, proof) => {
                self.visit_shuffle_stack(block, *id, stk, proof);
            }
            ShiftStack(id, stk, proof) => {
                self.visit_shift_stack(block, *id, stk, proof);
            }
            NameStack(id, name) => {
                self.visit_name_stack(block, *id, name);
            }
            TakeStack(id1, idxs, id2) => {
                self.visit_take_stack(block, *id1, idxs, *id2);
            }
            PileStacks(ids, id2) => {
                self.visit_pile_stack(block, ids, *id2);
            }
            InsertStack(id1, id2, stk, proof) => {
                self.visit_insert_stack(block, *id1, *id2, stk, proof);
            }
            PublishShares(id, shares, proof) => {
                self.visit_publish_shares(block, *id, shares, proof);
            }
            RandomSpec(id, spec) => {
                self.visit_random_spec(block, id, spec);
            }
            RandomEntropy(id, entropy) => {
                self.visit_random_entropy(block, id, entropy);
            }
            RandomReveal(id, share, proof) => {
                self.visit_random_reveal(block, id, share, proof);
            }
            Bytes(bytes) => {
                self.visit_bytes(block, bytes);
            }
        }
    }
    /// Visits a PublishKey payload
    fn visit_publish_key(&mut self, _block: &Block, _name: &str, _key: &PublicKey) {}
    /// Visits a OpenStack payload
    fn visit_open_stack(&mut self, _block: &Block, _stack: &Stack) {}
    /// Visits a MaskStack payload
    fn visit_mask_stack(
        &mut self,
        _block: &Block,
        _source: Id,
        _stack: &Stack,
        _proof: &[MaskProof],
    ) {
    }
    /// Visits a ShuffleStack payload
    fn visit_shuffle_stack(
        &mut self,
        _block: &Block,
        _source: Id,
        _stack: &Stack,
        _proof: &ShuffleProof,
    ) {
    }
    /// Visits a ShiftStack payload
    fn visit_shift_stack(&mut self, _block: &Block, _id: Id, _stack: &Stack, _proof: &ShiftProof) {}
    /// Visits a TakeStack payload
    fn visit_take_stack(&mut self, _block: &Block, _id1: Id, _idxs: &[usize], _id2: Id) {}
    /// Visits a PileStack payload
    fn visit_pile_stack(&mut self, _block: &Block, _ids: &[Id], _id2: Id) {}
    /// Visits a InsertToken payload
    fn visit_insert_stack(
        &mut self,
        _block: &Block,
        _id1: Id,
        _id2: Id,
        _stack: &Stack,
        _proof: &InsertProof,
    ) {
    }
    /// Visits a NameStack payload
    fn visit_name_stack(&mut self, _block: &Block, _id: Id, _name: &str) {}
    /// Visits a PublishShares payload
    fn visit_publish_shares(
        &mut self,
        _block: &Block,
        _id: Id,
        _shares: &[SecretShare],
        _proof: &[SecretShareProof],
    ) {
    }
    /// Visits a RandomSpec payload
    fn visit_random_spec(&mut self, _block: &Block, _name: &str, _spec: &str) {}
    /// Visits a RandomEntropy payload
    fn visit_random_entropy(&mut self, _block: &Block, _name: &str, _entropy: &Mask) {}
    /// Visits a RandomReveal payload
    fn visit_random_reveal(
        &mut self,
        _block: &Block,
        _name: &str,
        _share: &SecretShare,
        _proof: &SecretShareProof,
    ) {
    }
    /// Visits a Bytes payload
    fn visit_bytes(&mut self, _block: &Block, _bytes: &[u8]) {}
}
