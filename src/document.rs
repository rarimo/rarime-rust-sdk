use crate::RarimeError;
use crate::utils::poseidon_hash_32_bytes;
use anyhow::{Context, anyhow};
use digest::Digest;
use ff::*;
use num_bigint::BigInt;
use num_traits::One;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use simple_asn1::{ASN1Block, ASN1Class, BigUint, from_der, to_der};

enum ActiveAuthKey {
    Rsa { modulus: BigInt, exponent: BigInt },
    Ecdsa { key_bytes: Vec<u8> },
}

pub enum DocumentStatus {
    NOT_REGISTERED,
    REGISTERED_WITH_THIS_PK,
    REGISTERED_WITH_OTHER_PK,
}

pub struct RarimeDocument {
    pub(crate) data_group1: Vec<u8>,
    pub(crate) data_group15: Option<Vec<u8>>,
    pub(crate) aa_signature: Option<Vec<u8>>,
    pub(crate) aa_challenge: Option<Vec<u8>>,
    pub(crate) sod: Vec<u8>,
}

#[derive(Debug)]
enum SignatureDigestHashAlgorithm {
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
}

pub async fn get_document_status(
    passport_key: [u8; 32],
    profile_key: [u8; 32],
) -> Result<DocumentStatus, anyhow::Error> {
    let passport_info = contracts::get_passport_info(passport_key).await?;
    let zero_bytes: [u8; 32] = [0; 32];
    let hex_zero_bytes = hex::encode(&zero_bytes);
    let hex_active_identity = hex::encode(passport_info.passportInfo_.activeIdentity);
    let hex_profile_key = hex::encode(profile_key);

    if hex_active_identity == hex_zero_bytes {
        return Ok(DocumentStatus::NOT_REGISTERED);
    }
    if hex_active_identity == hex_profile_key {
        return Ok(DocumentStatus::REGISTERED_WITH_THIS_PK);
    }
    Ok(DocumentStatus::REGISTERED_WITH_OTHER_PK)
}

impl RarimeDocument {
    pub fn get_passport_key(&self) -> Result<[u8; 32], RarimeError> {
        if let Some(dg15_bytes) = &self.data_group15 {
            let key = Self::parse_dg15_pubkey(dg15_bytes).map_err(RarimeError::ParseDg15Error)?;
            return match key {
                ActiveAuthKey::Ecdsa { key_bytes } => {
                    RarimeDocument::extract_ecdsa_passport_key(&key_bytes)
                        .map_err(RarimeError::GetPassportKeyError)
                }
                ActiveAuthKey::Rsa { modulus, exponent } => {
                    RarimeDocument::extract_rsa_passport_key(&modulus, &exponent)
                        .map_err(RarimeError::GetPassportKeyError)
                }
            };
        }

        let passport_key = Self::get_passport_hash(&self.sod)
            .map_err(|e| RarimeError::GetPassportKeyError(e.into()))?;

        Ok(passport_key)
    }

    fn get_passport_hash(sod: &[u8]) -> Result<[u8; 32], anyhow::Error> {
        let sign_attr: ASN1Block = Self::extract_signed_attributes(&sod)?;

        let hash_algorithm = RarimeDocument::extract_hash_algorithm(&sod)?;

        let parsed_hash_algorithm = RarimeDocument::parse_hash_algorithm(&hash_algorithm)?;

        let mut sign_attr_bytes = to_der(&sign_attr)?;

        // The first byte must be 0xA0, which is the BER/DER tag for an **EXPLICIT**
        // Context-Specific element with tag number [0] (Class: Context-Specific, Tag: 0, Form: Constructed).
        //
        // This explicit tagging wraps the content, and the conversion (decoding/encoding)
        // is necessary to correctly process the inner structure (e.g., for hash/signature calculation,
        // as implied by the CMS standard, RFC 5652, Section 5.4).
        //
        // Ref: RFC 5652 (CMS) section 5.4, detailing the structure's ASN.1 definition.
        sign_attr_bytes[0] = 0x31;

        let hash_bytes = match parsed_hash_algorithm {
            SignatureDigestHashAlgorithm::SHA1 => Sha1::digest(&sign_attr_bytes).to_vec(),
            SignatureDigestHashAlgorithm::SHA224 => Sha224::digest(&sign_attr_bytes).to_vec(),
            SignatureDigestHashAlgorithm::SHA256 => Sha256::digest(&sign_attr_bytes).to_vec(),
            SignatureDigestHashAlgorithm::SHA384 => Sha384::digest(&sign_attr_bytes).to_vec(),
            SignatureDigestHashAlgorithm::SHA512 => Sha512::digest(&sign_attr_bytes).to_vec(),
        };
        let mut padded_hash = [0u8; 32];
        let len = std::cmp::min(hash_bytes.len(), 32);
        padded_hash[..len].copy_from_slice(&hash_bytes[..len]);

        let hash_int = BigInt::from_bytes_be(num_bigint::Sign::Plus, &padded_hash);

        let binary_string = hash_int.to_str_radix(2);
        let padded_binary_string = format!("{:0>256}", binary_string);
        let processed = &padded_binary_string[..252]
            .chars()
            .rev()
            .collect::<String>();
        let out = BigInt::parse_bytes(processed.as_bytes(), 2).expect("Invalid binary string");

        let poseidon_hash = poseidon_hash_32_bytes(vec![out])
            .map_err(|e| anyhow::anyhow!("Poseidon hash failed: {}", e))?;

        Ok(poseidon_hash)
    }

    fn extract_ecdsa_passport_key(key_bytes: &[u8]) -> Result<[u8; 32], anyhow::Error> {
        if key_bytes.len() != 65 || key_bytes[0] != 0x04 {
            return Err(anyhow::anyhow!("Invalid ECDSA key format"));
        }

        let x = BigInt::from_bytes_be(num_bigint::Sign::Plus, &key_bytes[1..33]);
        let y = BigInt::from_bytes_be(num_bigint::Sign::Plus, &key_bytes[33..65]);

        // 2^248
        let modulus = BigInt::one() << 248;

        let x_mod = &x % &modulus;
        let y_mod = &y % &modulus;

        let poseidon_hash = poseidon_hash_32_bytes(vec![x_mod, y_mod])
            .map_err(|e| anyhow::anyhow!("Poseidon hash failed: {}", e))?;

        Ok(poseidon_hash)
    }

    fn extract_rsa_passport_key(modulus: &BigInt, _exponent: &BigInt) -> anyhow::Result<[u8; 32]> {
        let bit_len = modulus.bits() as usize;
        let required_bits = 200 * 4 + 224; // 1024

        if bit_len < required_bits {
            return Err(anyhow::anyhow!(
                "RSA modulus too small to extract required bits"
            ));
        }

        let shift = bit_len - required_bits;
        let mut top_bits = modulus >> shift;

        let chunk_sizes = [224, 200, 200, 200, 200];
        let mut chunks = Vec::with_capacity(5);

        for &size in &chunk_sizes {
            let mask = (BigInt::one() << size) - 1;
            let chunk = &top_bits & &mask;
            chunks.push(chunk);

            top_bits = top_bits >> size;
        }

        chunks.reverse();

        let poseidon_result = poseidon_hash_32_bytes(chunks)
            .map_err(|e| anyhow::anyhow!("Poseidon hash failed: {}", e))?;

        Ok(poseidon_result)
    }

    fn parse_dg15_pubkey(dg15_bytes: &[u8]) -> Result<ActiveAuthKey, anyhow::Error> {
        let blocks = from_der(dg15_bytes).context("Failed to parse DG15 DER")?;

        let seq = match &blocks[0] {
            ASN1Block::Sequence(_, inner) => inner,
            ASN1Block::Explicit(class, _, tag, content)
                if *class == ASN1Class::Application && *tag == BigUint::from(15u32) =>
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

    fn extract_signed_attributes(sod_bytes: &[u8]) -> Result<ASN1Block, anyhow::Error> {
        let blocks = from_der(sod_bytes).context("Failed to parse DER")?;
        let root = blocks.get(0).context("Empty DER")?;

        let app23_seq = match root {
            ASN1Block::Explicit(class, _, tag, content)
                if *class == ASN1Class::Application && *tag == BigUint::from(23u32) =>
            {
                match content.as_ref() {
                    ASN1Block::Sequence(_, inner) => inner.clone(),
                    other => {
                        return Err(anyhow!(
                            "Expected SEQUENCE inside Application 23, got {:?}",
                            other
                        ));
                    }
                }
            }
            other => return Err(anyhow!("Expected Application 23 at root, got {:?}", other)),
        };

        let tagged0_inner_blocks: Vec<ASN1Block> = {
            let found = app23_seq
                .iter()
                .find(|b| match b {
                    ASN1Block::Explicit(_, _, tag, _) if *tag == BigUint::from(0u32) => true,
                    ASN1Block::Unknown(_, _, _, tag, _) => format!("{:?}", tag) == "0",
                    _ => false,
                })
                .context("No [0] tagged block found in Application 23 SEQUENCE")?;

            match found {
                ASN1Block::Explicit(_, _, _, content) => match content.as_ref() {
                    ASN1Block::Sequence(_, v) => v.clone(),
                    ASN1Block::Set(_, v) => v.clone(),
                    other => vec![other.clone()],
                },
                ASN1Block::Unknown(_, _, _, tag, raw_bytes) => {
                    let inner = from_der(&raw_bytes).context(format!(
                        "Failed to parse inner raw bytes from Unknown(ContextSpecific tag={:?})",
                        tag
                    ))?;
                    inner
                }
                other => match other {
                    ASN1Block::Sequence(_, v) => v.clone(),
                    ASN1Block::Set(_, v) => v.clone(),
                    _ => vec![other.clone()],
                },
            }
        };

        let final_seq: Vec<ASN1Block> = tagged0_inner_blocks
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

        let signed_attrs_block = final_seq
            .iter()
            .find_map(|elem| {
                if let ASN1Block::Explicit(_, _, tag, content) = elem {
                    if *tag == BigUint::from(0u32) {
                        return Some(match content.as_ref() {
                            ASN1Block::Set(_, v) => ASN1Block::Set(v.len(), v.clone()),
                            ASN1Block::Sequence(_, v) => ASN1Block::Sequence(v.len(), v.clone()),
                            other => other.clone(),
                        });
                    }
                }
                if let ASN1Block::Unknown(_, _, _, tag, raw_bytes) = elem {
                    if format!("{:?}", tag) == "0" {
                        if let Ok(parsed) = from_der(&raw_bytes) {
                            return if parsed.len() == 1 {
                                Some(parsed.into_iter().next().unwrap())
                            } else {
                                Some(ASN1Block::Sequence(parsed.len(), parsed))
                            };
                        }
                    }
                }

                None
            })
            .context("No [0] tag found inside final SEQUENCE")?;
        Ok(signed_attrs_block)
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
                            if oid_string.starts_with("1.2.840.113549") {
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
            oid.as_vec::<&BigUint>()?
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
}
