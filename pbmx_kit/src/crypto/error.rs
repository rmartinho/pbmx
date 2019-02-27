#![allow(deprecated)]

//! Error type

error_chain! {
    links {
        Serde(crate::serde::Error, crate::serde::ErrorKind);
    }

    foreign_links {
        Bytes(::bincode::Error);
        Base64(::base64::DecodeError);
        Hex(::std::num::ParseIntError);
    }

    errors {
        InvalidFingerprint {
            description("invalid fingerprint"),
            display("invalid fingerprint"),
        }
        UnknownPublicKey {
            description("unknown public key"),
            display("unknown public key"),
        }
        InvalidSecretShare {
            description("invalid secret share"),
            display("invalid secret share"),
        }
        NonPermutation {
            description("invalid permutation"),
            display("invalid permutation"),
        }
    }
}
