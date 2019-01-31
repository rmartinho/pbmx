//! Block payloads

use crate::{error::Error, Id};
use pbmx_curve::{
    keys::PublicKey,
    vtmf::{
        Mask, MaskProof, PrivateMaskProof, SecretShare, SecretShareProof, ShiftProof, ShuffleProof,
    },
};
use pbmx_serde::derive_base64_conversions;

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
    /// A stack name payload
    NameStack(Id, String),
    /// A stack mask payload
    MaskStack(Id, Vec<Mask>, Vec<MaskProof>),
    /// A stack shuffle payload
    ShuffleStack(Id, Vec<Mask>, ShuffleProof),
    /// A stack shift payload
    ShiftStack(Id, Vec<Mask>, ShiftProof),
    /// A secret share payload
    PublishShares(Id, Vec<SecretShare>, Vec<SecretShareProof>),
    /// A random bound payload
    StartRandom(u64),
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

    /// Gets a short string description of this payload
    pub fn display_short(&self) -> String {
        use Payload::*;
        match self {
            PublishKey(pk) => format!("publish key {:16}", pk.fingerprint()),
            OpenStack(stk) => format!("open stack {:16}", Id::of(stk).unwrap()),
            PrivateStack(id, stk, _) => format!(
                "private stack {1:16} \u{2282} {0:16}",
                id,
                Id::of(stk).unwrap()
            ),
            NameStack(id, name) => format!("name {:16} {}", id, name),
            MaskStack(id, stk, _) => {
                format!("mask {1:16} \u{21AC} {0:16}", id, Id::of(stk).unwrap())
            }
            ShuffleStack(id, stk, _) => {
                format!("shuffle {1:16} \u{224B} {0:16}", id, Id::of(stk).unwrap())
            }
            ShiftStack(id, stk, _) => {
                format!("cut {1:16} \u{21CB} {0:16}", id, Id::of(stk).unwrap())
            }
            PublishShares(id, ..) => format!("reveal {:16}", id),
            StartRandom(n) => format!("random {:16} < {}", n, self.id()),
            RandomShare(id, _) => format!("entropy {:16}", id),
            Bytes(bytes) => format!("message {}", &String::from_utf8_lossy(bytes)),
        }
    }
}

derive_base64_conversions!(Payload, Error);
