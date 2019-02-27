//! Cryptographic hash functions

/// The hash function used in PBMX
pub type Hash = sha3::Sha3_512;

/// The extended output function used in PBMX
pub type Xof = sha3::Shake256;
