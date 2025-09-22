use crate::{RarimeError, utils};
use anyhow::{Context, anyhow};
use ff::*;
use num_bigint::BigInt;
use num_traits::{One, Zero};
use poseidon_rs::{Fr, Poseidon};
use simple_asn1::{ASN1Block, ASN1Class, BigUint, from_der};

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
    pub fn get_passport_key(&self) -> Result<[u8; 32], RarimeError> {
        if let Some(dg15_bytes) = &self.data_group15 {
            let key = Self::parse_dg15_pubkey(dg15_bytes).map_err(RarimeError::ParseDg15Error)?;
            match key {
                ActiveAuthKey::Ecdsa { key_bytes } => {
                    return RarimeDocument::extract_ecdsa_passport_key(&key_bytes)
                        .map_err(RarimeError::GetPassportKeyError);
                }
                ActiveAuthKey::Rsa { modulus, exponent } => {
                    return RarimeDocument::extract_rsa_passport_key(&modulus, &exponent)
                        .map_err(RarimeError::GetPassportKeyError);
                }
            }
        }
        //  Passport without DG15 flow
        let sign_attr = Self::extract_authenticated_attributes(&self.sod);
        todo!()
    }
    fn extract_ecdsa_passport_key(key_bytes: &[u8]) -> Result<[u8; 32], anyhow::Error> {
        let x = BigInt::from_bytes_be(num_bigint::Sign::Plus, &key_bytes[..32]);
        let y = BigInt::from_bytes_be(num_bigint::Sign::Plus, &key_bytes[33..]);

        // 2^248
        let modulus = BigInt::one() << 248;

        let x_mod: BigInt = x % &modulus;
        let y_mod: BigInt = y % &modulus;

        let mut chunks_fr = Vec::with_capacity(2);
        for ch in &[x_mod, y_mod] {
            let bu = ch
                .to_biguint()
                .ok_or_else(|| anyhow::anyhow!("Negative coordinate?"))?;
            let dec = bu.to_str_radix(10);
            let fe = Fr::from_str(&dec)
                .ok_or_else(|| anyhow::anyhow!("Failed to convert chunk -> Fr: {}", dec))?;
            chunks_fr.push(fe);
        }

        // Poseidon hash
        let hasher = Poseidon::new();
        let h_fr = hasher
            .hash(chunks_fr)
            .map_err(|e| anyhow::anyhow!("Poseidon hash failed: {}", e))?;

        // Fr -> [u8; 32]
        let key_bytes = utils::fr_to_32bytes(&h_fr)?;
        Ok(key_bytes)
    }
    fn extract_rsa_passport_key(
        modulus: &BigInt,
        _exponent: &BigInt,
    ) -> Result<[u8; 32], anyhow::Error> {
        let required_bits = 200 * 4 + 224;
        let bit_len = modulus.bits();
        if bit_len < required_bits {
            return Err(anyhow!("RSA modulus too small to extract required bits"));
        }

        let shift = bit_len - required_bits;
        let top_bits = modulus >> shift;

        let chunk_sizes = [200, 200, 200, 200, 224];
        let mut chunks_bigint: Vec<BigInt> = vec![BigInt::zero(); chunk_sizes.len()];
        let mut current = top_bits.clone();
        for (i, &size) in chunk_sizes.iter().enumerate() {
            let mask = (BigInt::one() << size) - BigInt::one();
            let chunk = &current & &mask;
            chunks_bigint[chunk_sizes.len() - 1 - i] = chunk;
            current >>= size;
        }

        let mut chunks_fr: Vec<Fr> = Vec::with_capacity(chunks_bigint.len());
        for ch in chunks_bigint.iter() {
            let bu = ch.to_biguint().ok_or_else(|| anyhow!("chunk negative?"))?;
            let dec = bu.to_str_radix(10);
            let fe = Fr::from_str(&dec)
                .ok_or_else(|| anyhow!("Failed to convert chunk -> Fr: {}", dec))?;
            chunks_fr.push(fe);
        }

        let hasher = Poseidon::new();
        let h_fr = hasher
            .hash(chunks_fr)
            .map_err(|e| anyhow!("Poseidon hash failed: {}", e))?;

        let out = utils::fr_to_32bytes(&h_fr)?;
        Ok(out)
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

    fn extract_authenticated_attributes(sod_bytes: &[u8]) -> anyhow::Result<ASN1Block> {
        let blocks = from_der(sod_bytes).context("Failed to parse DER")?;

        let app23_seq = match &blocks[0] {
            ASN1Block::Explicit(class, _, tag, content)
                if *class == ASN1Class::Application && *tag == BigUint::from(23u32) =>
            {
                match content.as_ref() {
                    ASN1Block::Sequence(_, inner) => inner,
                    _ => anyhow::bail!("Expected SEQUENCE inside Application 23"),
                }
            }
            _ => anyhow::bail!("Expected Application 23"),
        };

        let tagged0 = app23_seq
            .iter()
            .find_map(|b| {
                if let ASN1Block::Explicit(_, _, tag, content) = b {
                    if *tag == BigUint::from(0u32) {
                        return Some(content.as_ref());
                    }
                }
                None
            })
            .context("No [0] tagged block found in Application 23 SEQUENCE")?;

        let inner_seq = match tagged0 {
            ASN1Block::Sequence(_, inner) => inner,
            _ => anyhow::bail!("Expected SEQUENCE inside [0]"),
        };

        let final_block = inner_seq
            .iter()
            .find_map(|b| {
                if let ASN1Block::Set(_, content) = b {
                    if let Some(ASN1Block::Sequence(_, inner)) = content.get(0) {
                        if inner.len() == 6 {
                            return Some(ASN1Block::Sequence(inner.len(), inner.clone()));
                        }
                    }
                }
                None
            })
            .context("No inner SET containing 6-element SEQUENCE found")?;

        Ok(final_block)
    }
}

#[derive(Debug)]
enum SignatureDigestHashAlgorithm {
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
}
fn extract_hash_algorithm(sod_bytes: &[u8]) -> anyhow::Result<ASN1Block> {
    let blocks = from_der(sod_bytes).context("Failed to parse DER")?;

    let app23_seq = match &blocks[0] {
        ASN1Block::Explicit(class, _, tag, content)
            if *class == ASN1Class::Application && *tag == BigUint::from(23u32) =>
        {
            match content.as_ref() {
                ASN1Block::Sequence(_, inner) => inner,
                _ => anyhow::bail!("Expected SEQUENCE inside Application 23"),
            }
        }
        _ => anyhow::bail!("Expected Application 23"),
    };

    let tagged0 = app23_seq
        .iter()
        .find_map(|b| {
            if let ASN1Block::Explicit(_, _, tag, content) = b {
                if *tag == BigUint::from(0u32) {
                    return Some(content.as_ref());
                }
            }
            None
        })
        .context("No [0] tagged block found in Application 23 SEQUENCE")?;

    let inner_seq = match tagged0 {
        ASN1Block::Sequence(_, inner) => inner,
        _ => anyhow::bail!("Expected SEQUENCE inside [0]"),
    };

    let sequence_block = inner_seq
        .iter()
        .find_map(|b| {
            if let ASN1Block::Set(_, content) = b {
                if let Some(ASN1Block::Sequence(_, inner)) = content.get(0) {
                    if inner.len() == 6 {
                        return Some(inner.clone());
                    }
                }
            }
            None
        })
        .context("No inner SET containing 6-element SEQUENCE found")?;

    let sig_alg_block = sequence_block
        .iter()
        .find_map(|b| {
            if let ASN1Block::Sequence(_, inner) = b {
                if inner.len() == 2 {
                    if let ASN1Block::ObjectIdentifier(tag, oid) = &inner[0] {
                        let oid_string = oid
                            .as_vec::<&BigUint>()
                            .unwrap()
                            .iter()
                            .map(|n| n.to_string())
                            .collect::<Vec<_>>()
                            .join(".");
                        if (oid_string.starts_with("1.2.840.113549.1.1")) {
                            return Some(ASN1Block::ObjectIdentifier(*tag, oid.clone()));
                        }
                    }
                }
            }
            None
        })
        .context("No RSA+SHA signature algorithm OID found")?;

    Ok(sig_alg_block)
}
fn parse_hash_algorithm(oid: &ASN1Block) -> anyhow::Result<SignatureDigestHashAlgorithm> {
    let oid_string = if let ASN1Block::ObjectIdentifier(_, oid) = oid {
        oid.as_vec::<&BigUint>()
            .unwrap()
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(".")
    } else {
        anyhow::bail!("Not an ObjectIdentifier");
    };

    match oid_string.as_str() {
        "1.2.840.113549.1.1.5" => Ok(SignatureDigestHashAlgorithm::SHA1),
        "1.2.840.113549.1.1.14" => Ok(SignatureDigestHashAlgorithm::SHA224),
        "1.2.840.113549.1.1.11" => Ok(SignatureDigestHashAlgorithm::SHA256),
        "1.2.840.113549.1.1.12" => Ok(SignatureDigestHashAlgorithm::SHA384),
        "1.2.840.113549.1.1.13" => Ok(SignatureDigestHashAlgorithm::SHA512),
        _ => anyhow::bail!("Unknown or unsupported RSA+SHA OID: {}", oid_string),
    }
}

pub enum DocumentStatus {
    REGISTRED_WITH_THIS_PK,
    REGISTRED_WITH_OTHER_PK,
    NOT_REGISTRED,
}
