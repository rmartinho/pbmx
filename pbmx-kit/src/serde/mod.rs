//! PBMX toolbox utilities

#[macro_use]
mod bytes;
mod protobuf;
pub use self::{
    bytes::{FromBase64, ToBase64},
    protobuf::Proto,
};

use crate::Error;
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};

/// A PBMX protocol message
pub trait Message: Sized {
    /// Encodes a value as a PBMX message
    fn encode(&self) -> Result<Vec<u8>, Error>;

    /// Encodes a value as a PBMX message in base64
    fn encode_base64(&self) -> Result<String, Error> {
        Ok(base64::encode_config(
            &self.encode()?,
            base64::URL_SAFE_NO_PAD,
        ))
    }

    /// Decodes a PBMX message into a value
    fn decode(buf: &[u8]) -> Result<Self, Error>;

    /// Decodes a base64 PBMX message into a value
    fn decode_base64(string: &str) -> Result<Self, Error> {
        let bytes =
            base64::decode_config(string, base64::URL_SAFE_NO_PAD).map_err(|_| Error::Decoding)?;
        Self::decode(&bytes)
    }
}

impl<T> Message for T
where
    T: Proto,
{
    fn encode(&self) -> Result<Vec<u8>, Error> {
        use prost::Message;
        let msg = self.to_proto()?;
        let raw_len = self.to_proto()?.encoded_len();
        let delim_len = prost::length_delimiter_len(raw_len);
        let format_len = prost::length_delimiter_len(FORMAT_NUMBER);
        let mut buf = Vec::with_capacity(raw_len + delim_len + format_len);
        prost::encode_length_delimiter(FORMAT_NUMBER, &mut buf).map_err(|_| Error::Encoding)?;
        msg.encode_length_delimited(&mut buf)
            .map_err(|_| Error::Encoding)?;
        Ok(buf)
    }

    fn decode(buf: &[u8]) -> Result<Self, Error> {
        use prost::Message;
        let format = prost::decode_length_delimiter(buf).map_err(|_| Error::Decoding)?;
        if format != FORMAT_NUMBER {
            return Err(Error::Decoding);
        }
        let format_len = prost::length_delimiter_len(format);
        let msg = <Self as Proto>::Message::decode_length_delimited(&buf[format_len..])
            .map_err(|_| Error::Decoding)?;
        Self::from_proto(&msg)
    }
}

const FORMAT_NUMBER: usize = 1;

/// Deserializes a series of Protocol Buffers messages
pub(crate) fn vec_from_proto<T: Proto>(v: &[T::Message]) -> Result<Vec<T>, Error> {
    v.iter().map(Proto::from_proto).collect()
}

/// Serializes a series of Protocol Buffers messages
pub(crate) fn vec_to_proto<T: Proto>(v: &[T]) -> Result<Vec<T::Message>, Error> {
    v.iter().map(Proto::to_proto).collect()
}

/// Deserializes a scalar
pub(crate) fn scalar_from_proto(v: &[u8]) -> Result<Scalar, Error> {
    if v.len() != 32 {
        return Err(Error::Decoding);
    }
    let mut buf = [0; 32];
    buf.copy_from_slice(v);
    Scalar::from_canonical_bytes(buf).ok_or(Error::Decoding)
}

/// Serializes a scalar
pub(crate) fn scalar_to_proto(s: &Scalar) -> Result<Vec<u8>, Error> {
    Ok(s.as_bytes().to_vec())
}

/// Deserializes a point
pub(crate) fn point_from_proto(v: &[u8]) -> Result<RistrettoPoint, Error> {
    if v.len() != 32 {
        return Err(Error::Decoding);
    }
    CompressedRistretto::from_slice(v)
        .decompress()
        .ok_or(Error::Decoding)
}

/// Serializes a point
pub(crate) fn point_to_proto(p: &RistrettoPoint) -> Result<Vec<u8>, Error> {
    Ok(p.compress().as_bytes().to_vec())
}

/// Deserializes a series of scalars
pub(crate) fn scalars_from_proto(v: &[Vec<u8>]) -> Result<Vec<Scalar>, Error> {
    v.iter().map(|v| scalar_from_proto(v)).collect()
}

/// Serializes a series of scalars
pub(crate) fn scalars_to_proto(s: &[Scalar]) -> Result<Vec<Vec<u8>>, Error> {
    s.iter().map(scalar_to_proto).collect()
}

/// Deserializes a series of points
pub(crate) fn points_from_proto(v: &[Vec<u8>]) -> Result<Vec<RistrettoPoint>, Error> {
    v.iter().map(|v| point_from_proto(v)).collect()
}

/// Serializes a series of points
pub(crate) fn points_to_proto(p: &[RistrettoPoint]) -> Result<Vec<Vec<u8>>, Error> {
    p.iter().map(point_to_proto).collect()
}
