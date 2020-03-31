//! PBMX toolbox utilities

#[macro_use]
mod macros;
mod bytes;
mod protobuf;
pub use self::{
    bytes::{FromBase64, FromBytes, ToBase64, ToBytes},
    protobuf::Proto,
};

use crate::Error;
use serde::ser::{Serialize, Serializer};
use std::{
    collections::{BTreeSet, HashMap},
    hash::{BuildHasher, Hash},
};

/// A PBMX protocol message
pub trait Message: Sized {
    /// Encodes a value as a PBMX message
    fn encode(&self) -> Result<Vec<u8>, Error>;
    /// Decodes a PBMX message into a value
    fn decode(buf: &[u8]) -> Result<Self, Error>;
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

/// Serializes a map as a flat vector
///
/// This implies that the keys can be reconstructed from the values alone.
/// The flat vector is ordered by the keys, so that the serialized form is
/// deterministic.
pub(crate) fn serialize_flat_map<K, V, H, S>(
    map: &HashMap<K, V, H>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    K: Eq + Ord + Hash,
    V: Serialize,
    H: BuildHasher,
    S: Serializer,
{
    let keys: BTreeSet<_> = map.keys().collect();
    let v: Vec<_> = keys.iter().map(|k| map.get(k).unwrap()).collect();
    v.serialize(serializer)
}

/// Deserializes a series of Protocol Buffers messages
pub(crate) fn vec_from_proto<T: Proto>(v: &[T::Message]) -> Result<Vec<T>, Error> {
    v.iter().map(Proto::from_proto).collect()
}

/// Serializes a series of Protocol Buffers messages
pub(crate) fn vec_to_proto<T: Proto>(v: &[T]) -> Result<Vec<T::Message>, Error> {
    v.iter().map(Proto::to_proto).collect()
}

pub(crate) mod scalar {
    use curve25519_dalek::scalar::Scalar;
    use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(s: &Scalar, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.as_bytes().serialize(serializer)
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Scalar, D::Error>
    where
        D: Deserializer<'de>,
    {
        Scalar::from_canonical_bytes(<[u8; 32]>::deserialize(deserializer)?)
            .ok_or_else(|| de::Error::custom("invalid scalar value"))
    }
}

pub(crate) mod point {
    use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
    use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(p: &RistrettoPoint, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        p.compress().as_bytes().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<RistrettoPoint, D::Error>
    where
        D: Deserializer<'de>,
    {
        CompressedRistretto(<[u8; 32]>::deserialize(deserializer)?)
            .decompress()
            .ok_or_else(|| de::Error::custom("invalid scalar value"))
    }
}

pub(crate) mod vec_scalar {
    use curve25519_dalek::scalar::Scalar;
    use serde::{
        de::{SeqAccess, Visitor},
        ser::SerializeSeq,
        Deserialize, Deserializer, Serialize, Serializer,
    };
    use std::fmt;

    struct Wrapper(Scalar);

    impl Serialize for Wrapper {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            super::scalar::serialize(&self.0, serializer)
        }
    }

    impl<'de> Deserialize<'de> for Wrapper {
        fn deserialize<D>(deserializer: D) -> Result<Wrapper, D::Error>
        where
            D: Deserializer<'de>,
        {
            Ok(Wrapper(super::scalar::deserialize(deserializer)?))
        }
    }

    pub fn serialize<S>(v: &Vec<Scalar>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(v.len()))?;
        for element in v {
            seq.serialize_element(&Wrapper(*element))?;
        }
        seq.end()
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Scalar>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct VecVisitor;

        impl<'de> Visitor<'de> for VecVisitor {
            type Value = Vec<Scalar>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("vector of scalars")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Vec<Scalar>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut v = if let Some(size) = seq.size_hint() {
                    Vec::with_capacity(size)
                } else {
                    Vec::new()
                };
                while let Some(Wrapper(s)) = seq.next_element::<Wrapper>()? {
                    v.push(s);
                }
                Ok(v)
            }
        }

        deserializer.deserialize_seq(VecVisitor)
    }
}

pub(crate) mod vec_point {
    use curve25519_dalek::ristretto::RistrettoPoint;
    use serde::{
        de::{SeqAccess, Visitor},
        ser::SerializeSeq,
        Deserialize, Deserializer, Serialize, Serializer,
    };
    use std::fmt;

    struct Wrapper(RistrettoPoint);

    impl Serialize for Wrapper {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            super::point::serialize(&self.0, serializer)
        }
    }

    impl<'de> Deserialize<'de> for Wrapper {
        fn deserialize<D>(deserializer: D) -> Result<Wrapper, D::Error>
        where
            D: Deserializer<'de>,
        {
            Ok(Wrapper(super::point::deserialize(deserializer)?))
        }
    }

    pub fn serialize<S>(v: &Vec<RistrettoPoint>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(v.len()))?;
        for element in v {
            seq.serialize_element(&Wrapper(*element))?;
        }
        seq.end()
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<RistrettoPoint>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct VecVisitor;

        impl<'de> Visitor<'de> for VecVisitor {
            type Value = Vec<RistrettoPoint>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("vector of points")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Vec<RistrettoPoint>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut v = if let Some(size) = seq.size_hint() {
                    Vec::with_capacity(size)
                } else {
                    Vec::new()
                };
                while let Some(Wrapper(s)) = seq.next_element::<Wrapper>()? {
                    v.push(s);
                }
                Ok(v)
            }
        }

        deserializer.deserialize_seq(VecVisitor)
    }
}
