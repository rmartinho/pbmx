//! Cryptographic hash functions

use digest::{
    generic_array::{typenum::U168, ArrayLength, GenericArray},
    BlockInput, ExtendableOutput, FixedOutput, Input, Reset, XofReader,
};
use std::{
    io::{self, Write},
    marker::PhantomData,
};
use tiny_keccak::{Hasher, KangarooTwelve, KangarooTwelveXof};

/// Hash function with 256-bit output
#[derive(Clone)]
pub struct Hash<N: ArrayLength<u8>> {
    k12: KangarooTwelve<&'static [u8]>,
    custom_string: &'static [u8],
    phantom: PhantomData<N>,
}

impl<N: ArrayLength<u8>> Hash<N> {
    /// Creates a customized instance of this hash function
    pub fn new(custom_string: &'static [u8]) -> Self {
        Self {
            k12: KangarooTwelve::new(custom_string),
            custom_string,
            phantom: PhantomData,
        }
    }
}

impl<N: ArrayLength<u8>> FixedOutput for Hash<N> {
    type OutputSize = N;

    fn fixed_result(self) -> GenericArray<u8, Self::OutputSize> {
        let mut out = GenericArray::default();
        self.k12.finalize(&mut out);
        out
    }
}

impl<N: ArrayLength<u8>> BlockInput for Hash<N> {
    type BlockSize = U168;
}

impl<N: ArrayLength<u8>> Input for Hash<N> {
    fn input<B: AsRef<[u8]>>(&mut self, data: B) {
        self.k12.update(data.as_ref())
    }
}

impl<N: ArrayLength<u8>> Reset for Hash<N> {
    fn reset(&mut self) {
        self.k12 = KangarooTwelve::new(self.custom_string);
    }
}

impl<N: ArrayLength<u8>> Write for Hash<N> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.k12.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Extendable output function
#[derive(Clone)]
pub struct Xof {
    k12: KangarooTwelve<&'static [u8]>,
    custom_string: &'static [u8],
}

impl Xof {
    /// Creates a customized instance of this XOF
    pub fn new(custom_string: &'static [u8]) -> Self {
        Self {
            k12: KangarooTwelve::new(custom_string),
            custom_string,
        }
    }
}

impl ExtendableOutput for Xof {
    type Reader = XofOutput;

    fn xof_result(self) -> Self::Reader {
        use tiny_keccak::IntoXof;
        XofOutput(self.k12.into_xof())
    }
}

impl Input for Xof {
    fn input<B: AsRef<[u8]>>(&mut self, data: B) {
        self.k12.update(data.as_ref())
    }
}

impl Reset for Xof {
    fn reset(&mut self) {
        self.k12 = KangarooTwelve::new(self.custom_string);
    }
}

impl Write for Xof {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.k12.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct XofOutput(KangarooTwelveXof);

impl XofReader for XofOutput {
    fn read(&mut self, buffer: &mut [u8]) {
        use tiny_keccak::Xof;
        self.0.squeeze(buffer);
    }
}
