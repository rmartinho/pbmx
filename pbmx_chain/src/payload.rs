//! Block payloads

use crate::{error::Error, Id};
use pbmx_curve::{
    keys::PublicKey,
    vtmf::{
        Mask, MaskProof, PrivateMaskProof, SecretShare, SecretShareProof, ShiftProof, ShuffleProof,
    },
};
use pbmx_serde::derive_base64_conversions;
use std::fmt::{self, Display, Formatter};

/// A PBMX message payload
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Payload {
    /// A public key payload
    PublishKey(PublicKey),
    /// An open stack payload
    OpenStack(Vec<Mask>),
    /// A private stack payload
    PrivateStack(Id, Vec<Mask>, Vec<PrivateMaskProof>),
    /// A stack mask payload
    MaskStack(Id, Vec<Mask>, Vec<MaskProof>),
    /// A stack shuffle payload
    ShuffleStack(Id, Vec<Mask>, ShuffleProof),
    /// A stack shift payload
    ShiftStack(Id, Vec<Mask>, ShiftProof),
    /// A stack name payload
    NameStack(Id, String),
    /// A substack payload
    TakeStack(Id, Vec<usize>, Vec<Mask>),
    /// A stack pile payload
    PileStacks(Vec<Id>, Vec<Mask>),
    /// A secret share payload
    PublishShares(Id, Vec<Mask>, Vec<SecretShare>, Vec<SecretShareProof>),
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
            PublishKey(pk) => write!(f, "publish key {:16}", pk.fingerprint()),
            OpenStack(stk) => write!(f, "open stack {:16}", Id::of(stk)?),
            PrivateStack(id, stk, _) => write!(
                f,
                "private stack {1:16} \u{2282} {0:16}",
                id,
                Id::of(stk).unwrap()
            ),
            NameStack(id, name) => write!(f, "name {:16} {}", id, name),
            MaskStack(id, stk, _) => {
                write!(f, "mask {1:16} \u{21AC} {0:16}", id, Id::of(stk).unwrap())
            }
            ShuffleStack(id, stk, _) => write!(
                f,
                "shuffle {1:16} \u{224B} {0:16}",
                id,
                Id::of(stk).unwrap()
            ),
            ShiftStack(id, stk, _) => {
                write!(f, "cut {1:16} \u{21CB} {0:16}", id, Id::of(stk).unwrap())
            }
            TakeStack(id, idxs, stk) => {
                write!(f, "take {:16}{:?} {:16}", id, idxs, Id::of(stk).unwrap())
            }
            PileStacks(ids, stk) => {
                write!(f, "pile {:16?} {:16}", ids, Id::of(stk).unwrap())
            }
            PublishShares(id, ..) => write!(f, "reveal {:16}", id),
            Bytes(bytes) => write!(f, "message {}", &String::from_utf8_lossy(bytes)),
        }
    }
}

derive_base64_conversions!(Payload, Error);
