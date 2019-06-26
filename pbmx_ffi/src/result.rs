use libc::c_int;
use std::{ops::Try, option::NoneError};

#[repr(transparent)]
pub struct PbmxResult(pub c_int);

impl PbmxResult {
    pub fn ok() -> Self {
        Self(1)
    }

    pub fn err() -> Self {
        Self(0)
    }
}

impl Try for PbmxResult {
    type Error = NoneError;
    type Ok = c_int;

    fn into_result(self) -> Result<Self::Ok, Self::Error> {
        if self.0 == 0 {
            Err(NoneError)
        } else {
            Ok(self.0)
        }
    }

    fn from_ok(v: Self::Ok) -> Self {
        Self(v)
    }

    fn from_error(_: Self::Error) -> Self {
        Self(0)
    }
}
