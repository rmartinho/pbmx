#![allow(deprecated)]

//! Error type

error_chain! {
    links {
        Serde(crate::serde::Error, crate::serde::ErrorKind);
        Crypto(crate::crypto::Error, crate::crypto::ErrorKind);
    }
}
