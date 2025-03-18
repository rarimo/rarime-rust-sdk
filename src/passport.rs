use serde::{Deserialize, Serialize};

use crate::{RarimeError, base64, rfc::rfc5652::SOD};

#[derive(Serialize, Deserialize)]
pub struct Passport {
    #[serde(
        serialize_with = "base64::serialize",
        deserialize_with = "base64::deserialize"
    )]
    pub dg1: Vec<u8>,
    #[serde(
        serialize_with = "base64::serialize_opt",
        deserialize_with = "base64::deserialize_opt"
    )]
    pub dg15: Option<Vec<u8>>,
    #[serde(
        serialize_with = "base64::serialize_opt",
        deserialize_with = "base64::deserialize_opt"
    )]
    pub aa_sig: Option<Vec<u8>>,
    #[serde(
        serialize_with = "base64::serialize_opt",
        deserialize_with = "base64::deserialize_opt"
    )]
    pub aa_challenge: Option<Vec<u8>>,
    #[serde(
        serialize_with = "base64::serialize",
        deserialize_with = "base64::deserialize"
    )]
    pub sod: Vec<u8>,
}

impl Passport {
    pub fn new(
        dg1: Vec<u8>,
        dg15: Option<Vec<u8>>,
        aa_sig: Option<Vec<u8>>,
        aa_challenge: Option<Vec<u8>>,
        sod: Vec<u8>,
    ) -> Self {
        Passport {
            dg1,
            dg15,
            aa_sig,
            aa_challenge,
            sod,
        }
    }

    pub fn parse_sod(&self) -> Result<SOD, RarimeError> {
        Ok(asn1::parse_single::<SOD>(&self.sod[4..])?)
    }
}
