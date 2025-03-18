use base64::prelude::*;
use serde::{Deserialize, Serialize};
use serde::{Deserializer, Serializer};

pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
    String::serialize(&BASE64_STANDARD.encode(v), s)
}

pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let v = String::deserialize(d)?;

    BASE64_STANDARD
        .decode(v.as_bytes())
        .map_err(|e| serde::de::Error::custom(e))
}

pub fn serialize_opt<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
    let base64 = match v {
        Some(v) => Some(BASE64_STANDARD.encode(v)),
        None => None,
    };
    <Option<String>>::serialize(&base64, s)
}

pub fn deserialize_opt<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
    let base64 = <Option<String>>::deserialize(d)?;
    match base64 {
        Some(v) => BASE64_STANDARD
            .decode(v.as_bytes())
            .map(|v| Some(v))
            .map_err(|e| serde::de::Error::custom(e)),
        None => Ok(None),
    }
}
