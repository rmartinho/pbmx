//! Block payloads

use crate::{
    chain::{block::Block, Id},
    crypto::{
        keys::PublicKey,
        vtmf::{
            EntanglementProof, Mask, MaskProof, SecretShare, SecretShareProof, ShiftProof,
            ShuffleProof, Stack,
        },
    },
    proto,
    serde::{vec_from_proto, vec_to_proto, Proto},
    Error, Result,
};
use std::{
    convert::TryFrom,
    fmt::{self, Display, Formatter},
};

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
    /// A secret share payload
    PublishShares(Id, Vec<SecretShare>, Vec<SecretShareProof>),
    /// An rng specification payload
    RandomSpec(String, String),
    /// An rng entropy payload
    RandomEntropy(String, Mask),
    /// An rng reveal payload
    RandomReveal(String, SecretShare, SecretShareProof),
    /// An entanglement proof payload
    ProveEntanglement(Vec<Id>, Vec<Id>, EntanglementProof),
    /// Raw text payload
    Text(String),
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
            PublishShares(id, ..) => write!(f, "reveal {:16}", id),
            RandomSpec(id, ..) => write!(f, "new rng {}", id),
            RandomEntropy(id, ..) => write!(f, "add entropy {}", id),
            RandomReveal(id, ..) => write!(f, "open rng {}", id),
            ProveEntanglement(ids1, ids2, ..) => write!(f, "entangled {:?} {:?}", ids1, ids2),
            Text(text) => write!(f, "text {}", text),
            Bytes(bytes) => write!(
                f,
                "binary {}",
                &base64::encode_config(bytes, base64::URL_SAFE_NO_PAD)
            ),
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
            ProveEntanglement(ids1, ids2, proof) => {
                self.visit_prove_entanglement(block, ids1, ids2, proof);
            }
            Text(text) => {
                self.visit_text(block, text);
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
    /// Visits a ProveEntanglement payload
    fn visit_prove_entanglement(
        &mut self,
        _block: &Block,
        _source_ids: &[Id],
        _shuffle_ids: &[Id],
        _proof: &EntanglementProof,
    ) {
    }
    /// Visits a Text payload
    fn visit_text(&mut self, _block: &Block, _text: &str) {}

    /// Visits a Bytes payload
    fn visit_bytes(&mut self, _block: &Block, _bytes: &[u8]) {}
}

impl Proto for Payload {
    type Message = proto::Payload;

    fn to_proto(&self) -> Result<proto::Payload> {
        use proto::payload::PayloadKind;

        let kind = match self {
            Payload::PublishKey(name, pk) => PayloadKind::PublishKey(proto::PublishKey {
                name: name.clone(),
                key: Some(pk.to_proto()?),
            }),
            Payload::OpenStack(stk) => PayloadKind::OpenStack(proto::OpenStack {
                stack: Some(stk.to_proto()?),
            }),
            Payload::NameStack(id, name) => PayloadKind::NameStack(proto::NameStack {
                id: id.to_vec(),
                name: name.clone(),
            }),
            Payload::MaskStack(id, stk, proof) => PayloadKind::MaskStack(proto::MaskStack {
                id: id.to_vec(),
                stack: Some(stk.to_proto()?),
                proofs: vec_to_proto(&proof)?,
            }),
            Payload::ShuffleStack(id, stk, proof) => {
                PayloadKind::ShuffleStack(proto::ShuffleStack {
                    id: id.to_vec(),
                    shuffle: Some(stk.to_proto()?),
                    proof: Some(proof.to_proto()?),
                })
            }
            Payload::ShiftStack(id, stk, proof) => PayloadKind::ShiftStack(proto::ShiftStack {
                id: id.to_vec(),
                shifted: Some(stk.to_proto()?),
                proof: Some(proof.to_proto()?),
            }),
            Payload::TakeStack(id1, idxs, id2) => PayloadKind::TakeStack(proto::TakeStack {
                source_id: id1.to_vec(),
                indices: idxs.iter().map(|&i| i as i64).collect(),
                result_id: id2.to_vec(),
            }),
            Payload::PileStacks(ids, id2) => PayloadKind::PileStacks(proto::PileStacks {
                source_ids: ids.iter().map(|id| id.to_vec()).collect(),
                result_id: id2.to_vec(),
            }),
            Payload::PublishShares(id, shares, proof) => {
                PayloadKind::PublishShares(proto::PublishShares {
                    id: id.to_vec(),
                    shares: vec_to_proto(&shares)?,
                    proofs: vec_to_proto(&proof)?,
                })
            }
            Payload::RandomSpec(name, spec) => PayloadKind::RandomSpec(proto::RandomSpec {
                name: name.clone(),
                spec: spec.clone(),
            }),
            Payload::RandomEntropy(name, entropy) => {
                PayloadKind::RandomEntropy(proto::RandomEntropy {
                    name: name.clone(),
                    entropy: Some(entropy.to_proto()?),
                })
            }
            Payload::RandomReveal(name, share, proof) => {
                PayloadKind::RandomReveal(proto::RandomReveal {
                    name: name.clone(),
                    share: Some(share.to_proto()?),
                    proof: Some(proof.to_proto()?),
                })
            }
            Payload::ProveEntanglement(ids1, ids2, proof) => {
                PayloadKind::ProveEntanglement(proto::ProveEntanglement {
                    source_ids: ids1.iter().map(|id| id.to_vec()).collect(),
                    shuffle_ids: ids2.iter().map(|id| id.to_vec()).collect(),
                    proof: Some(proof.to_proto()?),
                })
            }
            Payload::Text(text) => PayloadKind::Text(text.clone()),
            Payload::Bytes(bytes) => PayloadKind::Raw(bytes.clone()),
        };
        Ok(proto::Payload {
            payload_kind: Some(kind),
        })
    }

    fn from_proto(m: &proto::Payload) -> Result<Self> {
        fn do_it(m: &proto::Payload) -> Option<Payload> {
            use proto::payload::PayloadKind;

            Some(match m.payload_kind.as_ref()? {
                PayloadKind::PublishKey(p) => Payload::PublishKey(
                    p.name.clone(),
                    PublicKey::from_proto(p.key.as_ref()?).ok()?,
                ),
                PayloadKind::OpenStack(p) => {
                    Payload::OpenStack(Stack::from_proto(p.stack.as_ref()?).ok()?)
                }
                PayloadKind::MaskStack(p) => Payload::MaskStack(
                    Id::try_from(&p.id).ok()?,
                    Stack::from_proto(p.stack.as_ref()?).ok()?,
                    vec_from_proto(&p.proofs).ok()?,
                ),
                PayloadKind::ShuffleStack(p) => Payload::ShuffleStack(
                    Id::try_from(&p.id).ok()?,
                    Stack::from_proto(p.shuffle.as_ref()?).ok()?,
                    ShuffleProof::from_proto(p.proof.as_ref()?).ok()?,
                ),
                PayloadKind::ShiftStack(p) => Payload::ShiftStack(
                    Id::try_from(&p.id).ok()?,
                    Stack::from_proto(p.shifted.as_ref()?).ok()?,
                    ShiftProof::from_proto(p.proof.as_ref()?).ok()?,
                ),
                PayloadKind::NameStack(p) => {
                    Payload::NameStack(Id::try_from(&p.id).ok()?, p.name.clone())
                }
                PayloadKind::TakeStack(p) => Payload::TakeStack(
                    Id::try_from(&p.source_id).ok()?,
                    p.indices.iter().map(|&i| i as usize).collect(),
                    Id::try_from(&p.result_id).ok()?,
                ),
                PayloadKind::PileStacks(p) => Payload::PileStacks(
                    p.source_ids
                        .iter()
                        .map(|id| Id::try_from(id))
                        .collect::<Result<_>>()
                        .ok()?,
                    Id::try_from(&p.result_id).ok()?,
                ),
                PayloadKind::PublishShares(p) => Payload::PublishShares(
                    Id::try_from(&p.id).ok()?,
                    vec_from_proto(&p.shares).ok()?,
                    vec_from_proto(&p.proofs).ok()?,
                ),
                PayloadKind::RandomSpec(p) => Payload::RandomSpec(p.name.clone(), p.spec.clone()),
                PayloadKind::RandomEntropy(p) => Payload::RandomEntropy(
                    p.name.clone(),
                    Mask::from_proto(p.entropy.as_ref()?).ok()?,
                ),
                PayloadKind::RandomReveal(p) => Payload::RandomReveal(
                    p.name.clone(),
                    SecretShare::from_proto(p.share.as_ref()?).ok()?,
                    SecretShareProof::from_proto(p.proof.as_ref()?).ok()?,
                ),
                PayloadKind::ProveEntanglement(p) => Payload::ProveEntanglement(
                    p.source_ids
                        .iter()
                        .map(|id| Id::try_from(id))
                        .collect::<Result<_>>()
                        .ok()?,
                    p.shuffle_ids
                        .iter()
                        .map(|id| Id::try_from(id))
                        .collect::<Result<_>>()
                        .ok()?,
                    EntanglementProof::from_proto(p.proof.as_ref()?).ok()?,
                ),
                PayloadKind::Text(s) => Payload::Text(s.clone()),
                PayloadKind::Raw(p) => Payload::Bytes(p.clone()),
            })
        }
        do_it(m).ok_or(Error::Decoding)
    }
}
