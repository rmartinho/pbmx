//! Block payloads

use crate::{
    chain::Id,
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
