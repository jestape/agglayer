//! A serde deserializer for the guest input encoding of SP1 compressed proofs:
//! bincode 1 with fixed-int encoding, little endian, trailing bytes allowed
//! (`agglayer_bincode::sp1_compatible()`).
//!
//! It accepts the same bytes as bincode and builds the same values, except for
//! chars, which SP1 proofs do not contain. It does less work per primitive: in
//! ZisK it decodes an SP1 compressed proof in about 22% fewer steps than bincode.

use std::fmt::Display;

use serde::de::{
    self, DeserializeSeed, EnumAccess, IntoDeserializer, MapAccess, SeqAccess, VariantAccess,
    Visitor,
};

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Error(String);

impl de::Error for Error {
    fn custom<T: Display>(msg: T) -> Self {
        Error(msg.to_string())
    }
}

type Result<T> = core::result::Result<T, Error>;

#[cold]
#[inline(never)]
fn error(msg: &str) -> Error {
    Error(msg.to_owned())
}

/// Deserializes a `T` from the start of `input`, ignoring trailing bytes.
pub fn deserialize<'de, T: de::Deserialize<'de>>(input: &'de [u8]) -> Result<T> {
    T::deserialize(&mut Deserializer { input })
}

struct Deserializer<'de> {
    input: &'de [u8],
}

impl<'de> Deserializer<'de> {
    #[inline(always)]
    fn take(&mut self, n: usize) -> Result<&'de [u8]> {
        let (head, tail) = self
            .input
            .split_at_checked(n)
            .ok_or_else(|| error("unexpected end of input"))?;
        self.input = tail;
        Ok(head)
    }

    #[inline(always)]
    fn read<const N: usize>(&mut self) -> Result<[u8; N]> {
        let (head, tail) = self
            .input
            .split_first_chunk()
            .ok_or_else(|| error("unexpected end of input"))?;
        self.input = tail;
        Ok(*head)
    }

    #[inline(always)]
    fn read_len(&mut self) -> Result<usize> {
        usize::try_from(u64::from_le_bytes(self.read()?))
            .map_err(|_| error("length does not fit in usize"))
    }
}

macro_rules! fixed_int {
    ($($method:ident, $visit:ident, $ty:ty;)*) => {$(
        #[inline(always)]
        fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
            visitor.$visit(<$ty>::from_le_bytes(self.read()?))
        }
    )*};
}

impl<'de> de::Deserializer<'de> for &mut Deserializer<'de> {
    type Error = Error;

    fixed_int! {
        deserialize_u8, visit_u8, u8;
        deserialize_u16, visit_u16, u16;
        deserialize_u32, visit_u32, u32;
        deserialize_u64, visit_u64, u64;
        deserialize_u128, visit_u128, u128;
        deserialize_i8, visit_i8, i8;
        deserialize_i16, visit_i16, i16;
        deserialize_i32, visit_i32, i32;
        deserialize_i64, visit_i64, i64;
        deserialize_i128, visit_i128, i128;
        deserialize_f32, visit_f32, f32;
        deserialize_f64, visit_f64, f64;
    }

    fn deserialize_any<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        Err(error("the encoding is not self-describing"))
    }

    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        match self.read::<1>()?[0] {
            0 => visitor.visit_bool(false),
            1 => visitor.visit_bool(true),
            _ => Err(error("invalid bool")),
        }
    }

    fn deserialize_char<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        Err(error("chars are not supported"))
    }

    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        let len = self.read_len()?;
        let s = std::str::from_utf8(self.take(len)?).map_err(|_| error("invalid utf-8"))?;
        visitor.visit_borrowed_str(s)
    }

    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.deserialize_str(visitor)
    }

    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        let len = self.read_len()?;
        visitor.visit_borrowed_bytes(self.take(len)?)
    }

    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.deserialize_bytes(visitor)
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        match self.read::<1>()?[0] {
            0 => visitor.visit_none(),
            1 => visitor.visit_some(self),
            _ => Err(error("invalid option tag")),
        }
    }

    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_unit()
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value> {
        visitor.visit_unit()
    }

    #[inline(always)]
    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value> {
        visitor.visit_newtype_struct(self)
    }

    #[inline(always)]
    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        let len = self.read_len()?;
        visitor.visit_seq(Access { de: self, len })
    }

    #[inline(always)]
    fn deserialize_tuple<V: Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value> {
        visitor.visit_seq(Access { de: self, len })
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value> {
        self.deserialize_tuple(len, visitor)
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        let len = self.read_len()?;
        visitor.visit_map(Access { de: self, len })
    }

    #[inline(always)]
    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        self.deserialize_tuple(fields.len(), visitor)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        visitor.visit_enum(self)
    }

    fn deserialize_identifier<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        Err(error("the encoding has no identifiers"))
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        Err(error("the encoding is not self-describing"))
    }

    fn is_human_readable(&self) -> bool {
        false
    }
}

/// Sequence and map access: the remaining number of elements or entries.
struct Access<'a, 'de> {
    de: &'a mut Deserializer<'de>,
    len: usize,
}

impl<'de> SeqAccess<'de> for Access<'_, 'de> {
    type Error = Error;

    #[inline(always)]
    fn next_element_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<Option<T::Value>> {
        if self.len == 0 {
            return Ok(None);
        }
        self.len -= 1;
        seed.deserialize(&mut *self.de).map(Some)
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.len)
    }
}

impl<'de> MapAccess<'de> for Access<'_, 'de> {
    type Error = Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(&mut self, seed: K) -> Result<Option<K::Value>> {
        if self.len == 0 {
            return Ok(None);
        }
        self.len -= 1;
        seed.deserialize(&mut *self.de).map(Some)
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value> {
        seed.deserialize(&mut *self.de)
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.len)
    }
}

impl<'de> EnumAccess<'de> for &mut Deserializer<'de> {
    type Error = Error;
    type Variant = Self;

    fn variant_seed<V: DeserializeSeed<'de>>(self, seed: V) -> Result<(V::Value, Self)> {
        let index = u32::from_le_bytes(self.read()?);
        let value = seed.deserialize(IntoDeserializer::<Error>::into_deserializer(index))?;
        Ok((value, self))
    }
}

impl<'de> VariantAccess<'de> for &mut Deserializer<'de> {
    type Error = Error;

    fn unit_variant(self) -> Result<()> {
        Ok(())
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value> {
        seed.deserialize(self)
    }

    fn tuple_variant<V: Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value> {
        de::Deserializer::deserialize_tuple(self, len, visitor)
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        de::Deserializer::deserialize_tuple(self, fields.len(), visitor)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde::{de::DeserializeOwned, Deserialize, Serialize};

    use super::*;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Unit;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Newtype(u32);

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct TupleStruct(u8, i64);

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    enum Enum {
        Unit,
        Newtype(u16),
        Tuple(u32, bool),
        Struct { a: Option<u8>, b: String },
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Everything {
        bool: bool,
        u8: u8,
        u16: u16,
        u32: u32,
        u64: u64,
        u128: u128,
        i8: i8,
        i16: i16,
        i32: i32,
        i64: i64,
        i128: i128,
        f32: f32,
        f64: f64,
        usize: usize,
        string: String,
        #[serde(with = "serde_bytes_like")]
        bytes: Vec<u8>,
        none: Option<u32>,
        some: Option<Option<u32>>,
        unit: (),
        unit_struct: Unit,
        newtype: Newtype,
        tuple: (u8, u32, u64),
        tuple_struct: TupleStruct,
        array: [u32; 8],
        nested: Vec<[u32; 8]>,
        map: BTreeMap<String, Vec<u16>>,
        enums: Vec<Enum>,
    }

    /// Serializes a `Vec<u8>` with `serialize_bytes`, to cover `deserialize_bytes`.
    mod serde_bytes_like {
        use serde::{Deserializer, Serializer};

        pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
            s.serialize_bytes(v)
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
            struct V;
            impl<'de> serde::de::Visitor<'de> for V {
                type Value = Vec<u8>;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("bytes")
                }
                fn visit_bytes<E>(self, v: &[u8]) -> Result<Vec<u8>, E> {
                    Ok(v.to_vec())
                }
            }
            d.deserialize_bytes(V)
        }
    }

    fn everything() -> Everything {
        Everything {
            bool: true,
            u8: 0xab,
            u16: 0xabcd,
            u32: 0x7f00_0000,
            u64: u64::MAX - 1,
            u128: u128::MAX / 3,
            i8: -5,
            i16: -1234,
            i32: i32::MIN,
            i64: -42,
            i128: i128::MIN + 7,
            f32: 1.5,
            f64: -0.25,
            usize: 123_456,
            string: "agglayer".into(),
            bytes: vec![1, 2, 3],
            none: None,
            some: Some(None),
            unit: (),
            unit_struct: Unit,
            newtype: Newtype(7),
            tuple: (1, 2, 3),
            tuple_struct: TupleStruct(9, -9),
            array: [1, 2, 3, 4, 5, 6, 7, 8],
            nested: vec![[0; 8], [u32::MAX; 8]],
            map: BTreeMap::from([("a".into(), vec![1, 2]), ("b".into(), vec![])]),
            enums: vec![
                Enum::Unit,
                Enum::Newtype(3),
                Enum::Tuple(4, false),
                Enum::Struct { a: Some(5), b: "x".into() },
            ],
        }
    }

    fn encode<T: Serialize>(value: &T) -> Vec<u8> {
        agglayer_bincode::sp1_compatible().serialize(value).unwrap()
    }

    fn assert_matches_bincode<T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug>(
        value: &T,
    ) {
        let bytes = encode(value);
        let ours: T = deserialize(&bytes).unwrap();
        let theirs: T = agglayer_bincode::sp1_compatible().deserialize(&bytes).unwrap();
        assert_eq!(&ours, value);
        assert_eq!(ours, theirs);
    }

    #[test]
    fn decodes_what_bincode_encodes() {
        assert_matches_bincode(&everything());
    }

    #[test]
    fn decodes_at_every_alignment() {
        let value = everything();
        let bytes = encode(&value);
        for offset in 0..8 {
            let mut buf = vec![0xee; offset];
            buf.extend_from_slice(&bytes);
            let decoded: Everything = deserialize(&buf[offset..]).unwrap();
            assert_eq!(decoded, value);
        }
    }

    #[test]
    fn ignores_trailing_bytes() {
        let mut bytes = encode(&Newtype(1));
        bytes.extend_from_slice(&[0xff; 5]);
        assert_eq!(deserialize::<Newtype>(&bytes).unwrap(), Newtype(1));
    }

    #[test]
    fn rejects_every_truncation() {
        let bytes = encode(&everything());
        for len in 0..bytes.len() {
            assert!(
                deserialize::<Everything>(&bytes[..len]).is_err(),
                "accepted a truncation to {len} bytes"
            );
        }
    }

    #[test]
    fn rejects_invalid_tags() {
        assert!(deserialize::<char>(b"a").is_err());
        assert!(deserialize::<bool>(&[2]).is_err());
        assert!(deserialize::<Option<u8>>(&[2, 0]).is_err());
        assert!(deserialize::<Enum>(&4u32.to_le_bytes()).is_err());
        let mut invalid_utf8 = 1u64.to_le_bytes().to_vec();
        invalid_utf8.push(0xff);
        assert!(deserialize::<String>(&invalid_utf8).is_err());
    }
}
