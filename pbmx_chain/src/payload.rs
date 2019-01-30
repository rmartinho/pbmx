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
}

derive_base64_conversions!(Payload, Error);
