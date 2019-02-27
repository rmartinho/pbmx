#![allow(deprecated)]

//! Error type

error_chain! {
    foreign_links {
        Bytes(::bincode::Error);
        Base64(::base64::DecodeError);
        Hex(::std::num::ParseIntError);
    }
}
