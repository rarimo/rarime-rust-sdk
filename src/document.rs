use crate::RarimeError;
use anyhow::Context;
use num_bigint::BigInt;
use simple_asn1::{ASN1Block, BigUint, from_der};

pub enum ActiveAuthKey {
    Rsa { modulus: BigInt, exponent: BigInt },
    Ecdsa { key_bytes: Vec<u8> },
}

pub struct RarimeDocument {
    pub(crate) data_group1: Vec<u8>,
    pub(crate) data_group15: Option<Vec<u8>>,
    pub(crate) aa_signature: Option<Vec<u8>>,
    pub(crate) aa_challenge: Option<Vec<u8>>,
    pub(crate) sod: Vec<u8>,
}

impl RarimeDocument {
    pub fn get_passport_key(&self) -> Result<Vec<u8>, RarimeError> {
        if let Some(dg15_bytes) = &self.data_group15 {
            let key = Self::parse_dg15_pubkey(dg15_bytes).map_err(RarimeError::ParseDg15Error)?;
            match key {
                ActiveAuthKey::Ecdsa { key_bytes } => {
                    return Ok(key_bytes.to_vec());
                }
                ActiveAuthKey::Rsa { modulus, exponent } => {
                    todo!()
                }
            }
        }
        todo!()
    }

    fn parse_dg15_pubkey(dg15_bytes: &[u8]) -> Result<ActiveAuthKey, anyhow::Error> {
        let blocks = from_der(dg15_bytes).context("Failed to parse DG15 DER")?;

        let seq = match &blocks[0] {
            ASN1Block::Sequence(_, inner) => inner,
            ASN1Block::Explicit(class, _, tag, content)
                if *class == simple_asn1::ASN1Class::Application
                    && *tag == BigUint::from(15u32) =>
            {
                match content.as_ref() {
                    ASN1Block::Sequence(_, inner2) => inner2,
                    _ => anyhow::bail!("Expected SEQUENCE inside Application 15"),
                }
            }
            _ => anyhow::bail!("Expected SEQUENCE or Application 15 for DG15"),
        };

        let _algorithm = &seq[0];
        let bitstring = match &seq[1] {
            ASN1Block::BitString(_, _, bs_bytes) => bs_bytes,
            _ => anyhow::bail!("Expected BIT STRING for subjectPublicKey"),
        };

        if let Ok(inner_blocks) = from_der(bitstring) {
            if let ASN1Block::Sequence(_, rsa_inner) = &inner_blocks[0] {
                let modulus = match &rsa_inner[0] {
                    ASN1Block::Integer(_, n) => n.clone(),
                    _ => anyhow::bail!("Expected INTEGER modulus"),
                };
                let exponent = match &rsa_inner[1] {
                    ASN1Block::Integer(_, e) => e.clone(),
                    _ => anyhow::bail!("Expected INTEGER exponent"),
                };
                return Ok(ActiveAuthKey::Rsa { modulus, exponent });
            }
        }

        Ok(ActiveAuthKey::Ecdsa {
            key_bytes: bitstring.clone(),
        })
    }
}

pub enum DocumentStatus {
    REGISTRED_WITH_THIS_PK,
    REGISTRED_WITH_OTHER_PK,
    NOT_REGISTRED,
}
