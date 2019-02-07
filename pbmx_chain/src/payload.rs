//! Block payloads

use crate::{error::Error, Id};
use pbmx_curve::{
    keys::PublicKey,
    vtmf::{MaskProof, SecretShare, SecretShareProof, ShiftProof, ShuffleProof, Stack},
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
    TakeStack(Id, Vec<usize>, Stack),
    /// A stack pile payload
    PileStacks(Vec<Id>, Stack),
    /// A secret share payload
    PublishShares(Id, Vec<SecretShare>, Vec<SecretShareProof>),
    /// A stack unmask payload
    UnmaskStack(Id, Stack),
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
            OpenStack(stk) => write!(f, "open stack {:16}", stk.id()),
            NameStack(id, name) => write!(f, "name {:16} {}", id, name),
            MaskStack(id, stk, _) => write!(f, "mask {1:16} \u{21AC} {0:16}", id, stk.id()),
            ShuffleStack(id, stk, _) => write!(f, "shuffle {1:16} \u{224B} {0:16}", id, stk.id()),
            ShiftStack(id, stk, _) => write!(f, "cut {1:16} \u{21CB} {0:16}", id, stk.id()),
            TakeStack(id, idxs, stk) => write!(f, "take {:16}{:?} {:16}", id, idxs, stk.id()),
            PileStacks(ids, stk) => write!(f, "pile {:16?} {:16}", ids, stk.id()),
            PublishShares(id, ..) => write!(f, "reveal {:16}", id),
            UnmaskStack(id, stk) => write!(f, "unmask {:16} {:16}", id, stk.id()),
            Bytes(bytes) => write!(f, "message {}", &String::from_utf8_lossy(bytes)),
        }
    }
}

derive_base64_conversions!(Payload, Error);
