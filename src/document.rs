use crate::hash_algorithm::HashAlgorithm;
use crate::signature_algorithm::SignatureAlgorithm;
use crate::utils::{
    convert_asn1_to_pem, extract_oid_from_asn1, get_smt_proof_index, poseidon_hash_32_bytes,
    vec_u8_to_u8_32,
};
use crate::{QueryProofParams, RarimeError, RarimeUtils};
use chrono::Utc;
use contracts::{ContractsProvider, ContractsProviderConfig};
use num_bigint::BigInt;
use num_traits::{One, Zero};
use proofs::{LiteRegisterProofInput, ProofProvider, QueryProofInput};
use simple_asn1::{ASN1Block, ASN1Class, BigUint, from_der, to_der};

enum ActiveAuthKey {
    Rsa { modulus: BigInt, exponent: BigInt },
    Ecdsa { key_bytes: Vec<u8> },
}

#[derive(Debug)]
pub enum DocumentStatus {
    NotRegistered,
    RegisteredWithThisPk,
    RegisteredWithOtherPk,
}

#[derive(Clone)]
pub struct RarimePassport {
    pub data_group1: Vec<u8>,
    pub data_group15: Option<Vec<u8>>,
    pub aa_signature: Option<Vec<u8>>,
    pub aa_challenge: Option<Vec<u8>>,
    pub sod: Vec<u8>,
}

pub(crate) async fn get_document_status(
    passport_key: &[u8; 32],
    profile_key: &[u8; 32],
    config: ContractsProviderConfig,
) -> Result<DocumentStatus, RarimeError> {
    let contacts = ContractsProvider::new(config);
    let passport_info = contacts.get_passport_info(passport_key).await?;

    let zero_bytes: [u8; 32] = [0u8; 32];

    let active_identity = passport_info.passportInfo_.activeIdentity;

    if active_identity == zero_bytes {
        return Ok(DocumentStatus::NotRegistered);
    }
    if active_identity == profile_key {
        return Ok(DocumentStatus::RegisteredWithThisPk);
    }
    Ok(DocumentStatus::RegisteredWithOtherPk)
}

impl RarimePassport {
    pub(crate) fn get_passport_key(&self) -> Result<[u8; 32], RarimeError> {
        if let Some(dg15_bytes) = &self.data_group15 {
            let key = Self::parse_dg15_pubkey(dg15_bytes)?;
            return match key {
                ActiveAuthKey::Ecdsa { key_bytes } => {
                    RarimePassport::extract_ecdsa_passport_key(&key_bytes)
                }
                ActiveAuthKey::Rsa { modulus, exponent } => {
                    RarimePassport::extract_rsa_passport_key(&modulus, &exponent)
                }
            };
        }

        let passport_key = self.get_passport_hash()?;

        Ok(passport_key)
    }

    pub(crate) fn get_passport_hash(&self) -> Result<[u8; 32], RarimeError> {
        let sign_attr: ASN1Block = self.extract_signed_attributes()?;

        let hash_block = RarimePassport::extract_passport_signature_block(&self)?;
        let parsed_oid = extract_oid_from_asn1(&hash_block)?;
        let parsed_hash_algorithm = HashAlgorithm::from_oid(parsed_oid)?;

        let sign_attr_bytes = to_der(&sign_attr).map_err(|e| RarimeError::ASN1EncodeError(e))?;

        let hash = parsed_hash_algorithm.get_hash_fixed32(&sign_attr_bytes);

        let mut out = BigInt::zero();
        let mut acc: u64 = 0;
        let mut acc_bits = 0usize;
        for i in (0..252).rev() {
            acc = (acc << 1) | (((hash[i / 8] >> (7 - (i % 8))) & 1) as u64);
            acc_bits += 1;
            if acc_bits == 64 {
                out = (out << 64) | BigInt::from(acc);
                acc = 0;
                acc_bits = 0;
            }
        }
        if acc_bits > 0 {
            out = (out << acc_bits) | BigInt::from(acc);
        }

        let poseidon_hash = poseidon_hash_32_bytes(&[out])?;

        Ok(poseidon_hash)
    }

    fn extract_ecdsa_passport_key(key_bytes: &[u8]) -> Result<[u8; 32], RarimeError> {
        if key_bytes.len() != 65 || key_bytes[0] != 0x04 {
            return Err(RarimeError::UnsupportedPassportKey);
        }

        let x = BigInt::from_bytes_be(num_bigint::Sign::Plus, &key_bytes[1..33]);
        let y = BigInt::from_bytes_be(num_bigint::Sign::Plus, &key_bytes[33..65]);

        // 2^248
        let modulus = BigInt::one() << 248;

        let x_mod = &x % &modulus;
        let y_mod = &y % &modulus;

        let poseidon_hash = poseidon_hash_32_bytes(&[x_mod, y_mod])?;

        Ok(poseidon_hash)
    }

    fn extract_rsa_passport_key(
        modulus: &BigInt,
        _exponent: &BigInt,
    ) -> Result<[u8; 32], RarimeError> {
        let bit_len = modulus.bits() as usize;
        let required_bits = 200 * 4 + 224; // 1024

        if bit_len < required_bits {
            return Err(RarimeError::UnsupportedPassportKey);
        }

        let shift = bit_len - required_bits;
        let mut top_bits = modulus >> shift;

        let chunk_sizes = [224, 200, 200, 200, 200];
        let mut chunks = Vec::with_capacity(5);

        for &size in &chunk_sizes {
            let mask = (BigInt::one() << size) - 1;
            let chunk = &top_bits & &mask;
            chunks.push(chunk);

            top_bits >>= size;
        }

        chunks.reverse();

        let poseidon_result = poseidon_hash_32_bytes(&chunks)?;

        Ok(poseidon_result)
    }
    pub fn get_dg_hash_algorithm(&self) -> Result<HashAlgorithm, RarimeError> {
        let dg_hash_algo_block = self.extract_dg_hash_algo_block()?;
        let parsed_oid = extract_oid_from_asn1(&dg_hash_algo_block)?;

        let passport_signature = HashAlgorithm::from_oid(parsed_oid)?;
        return Ok(passport_signature);
    }

    pub fn extract_signature(&self) -> Result<Vec<u8>, RarimeError> {
        let blocks = from_der(&self.sod).map_err(|e| RarimeError::ASN1DecodeError(e))?;

        let app23_seq = match &blocks[0] {
            ASN1Block::Explicit(class, _, tag, content)
                if *class == ASN1Class::Application && *tag == BigUint::from(23u32) =>
            {
                match content.as_ref() {
                    ASN1Block::Sequence(_, inner) => inner,
                    _ => {
                        return Err(RarimeError::ASN1RouteError(
                            "Expected SEQUENCE inside Application 23".to_string(),
                        ));
                    }
                }
            }
            _ => {
                return Err(RarimeError::ASN1RouteError(
                    "Expected Application 23".to_string(),
                ));
            }
        };

        let tagged0 = app23_seq
            .iter()
            .find_map(|b| {
                if let ASN1Block::Explicit(_, _, tag, content) = b
                    && *tag == BigUint::from(0u32)
                {
                    return Some(content.as_ref());
                }
                None
            })
            .ok_or(RarimeError::ASN1RouteError(
                "No [0] tagged block found in Application 23 SEQUENCE".to_string(),
            ))?;

        let inner_seq = match tagged0 {
            ASN1Block::Sequence(_, inner) => inner,
            _ => {
                return Err(RarimeError::ASN1RouteError(
                    "Expected SEQUENCE inside [0]".to_string(),
                ));
            }
        };

        let sequence_block = inner_seq
            .iter()
            .find_map(|b| {
                if let ASN1Block::Set(_, content) = b
                    && let Some(ASN1Block::Sequence(_, inner)) = content.first()
                    && inner.len() == 6
                {
                    return Some(inner.clone());
                }
                None
            })
            .ok_or(RarimeError::ASN1RouteError(
                "No inner SET containing 6-element SEQUENCE found".to_string(),
            ))?;

        let signature_bytes: Vec<u8> = sequence_block
            .iter()
            .find_map(|b| {
                if let ASN1Block::OctetString(_, data) = b {
                    return Some(data.to_vec());
                }
                None
            })
            .ok_or(RarimeError::ASN1RouteError(
                "No OctetString (signature) found in the expected sequence.".to_string(),
            ))?;

        Ok(signature_bytes)
    }

    fn extract_dg_hash_algo_block(&self) -> Result<ASN1Block, RarimeError> {
        let sod_bytes = &self.sod;
        let blocks = from_der(sod_bytes).map_err(|e| RarimeError::ASN1DecodeError(e))?;

        let app23_block = blocks
            .iter()
            .find(|b| {
                matches!(b, ASN1Block::Explicit(class, _, tag, _)
            if *class == ASN1Class::Application && *tag == BigUint::from(23u32))
            })
            .ok_or(RarimeError::ASN1RouteError(
                "Expected Application 23 SEQUENCE in the root".to_string(),
            ))?;

        let seq_in_app23 = match app23_block {
            ASN1Block::Explicit(_, _, _, content) => match content.as_ref() {
                ASN1Block::Sequence(_, inner) => inner,
                _ => {
                    return Err(RarimeError::ASN1RouteError(
                        "Expected SEQUENCE inside Application 23".to_string(),
                    ));
                }
            },
            _ => {
                return Err(RarimeError::ASN1RouteError(
                    "Expected Explicit block for Application[23]".to_string(),
                ));
            }
        };

        let tagged0_block = seq_in_app23
            .iter()
            .find(|b| matches!(b, ASN1Block::Explicit(_, _, tag, _) if *tag == BigUint::from(0u32)))
            .ok_or(RarimeError::ASN1RouteError(
                "No [0] tagged block found".to_string(),
            ))?;

        let seq_in_tagged0 = match tagged0_block {
            ASN1Block::Explicit(_, _, _, content) => match content.as_ref() {
                ASN1Block::Sequence(_, inner) => inner,
                _ => {
                    return Err(RarimeError::ASN1RouteError(
                        "Expected SEQUENCE inside [0]".to_string(),
                    ));
                }
            },
            _ => {
                return Err(RarimeError::ASN1RouteError(
                    "Expected Explicit block for [0]".to_string(),
                ));
            }
        };

        let set_block = seq_in_tagged0
            .iter()
            .find(|b| matches!(b, ASN1Block::Set(_, _)))
            .ok_or(RarimeError::ASN1RouteError(
                ("No SET found inside [0] SEQUENCE").to_string(),
            ))?;

        let inner_seq = if let ASN1Block::Set(_, content) = set_block {
            let seq = content
                .get(0)
                .ok_or(RarimeError::ASN1RouteError(("SET is empty").to_string()))?;
            match seq {
                ASN1Block::Sequence(_, _) => seq,
                _ => {
                    return Err(RarimeError::ASN1RouteError(
                        "Expected SEQUENCE as first element of SET".to_string(),
                    ));
                }
            }
        } else {
            return Err(RarimeError::ASN1RouteError(
                "Expected SET block".to_string(),
            ));
        };

        let oid_block = if let ASN1Block::Sequence(_, seq_content) = inner_seq {
            let oid = seq_content.get(0).ok_or(RarimeError::ASN1RouteError(
                ("Inner SEQUENCE is empty").to_string(),
            ))?;
            match oid {
                ASN1Block::ObjectIdentifier(_, _) => oid.clone(),
                _ => {
                    return Err(RarimeError::ASN1RouteError(
                        "Expected ObjectIdentifier as first element of inner SEQUENCE".to_string(),
                    ));
                }
            }
        } else {
            return Err(RarimeError::ASN1RouteError(
                "Expected ObjectIdentifier as first element of inner SEQUENCE".to_string(),
            ));
        };

        Ok(oid_block)
    }

    pub fn extract_dg_hash_algo(&self) -> Result<ASN1Block, RarimeError> {
        let sod_bytes = &self.sod;
        let blocks = from_der(sod_bytes).map_err(|e| RarimeError::ASN1DecodeError(e))?;

        let app23_block = blocks
            .iter()
            .find(|b| {
                matches!(b, ASN1Block::Explicit(class, _, tag, _)
            if *class == ASN1Class::Application && *tag == BigUint::from(23u32))
            })
            .ok_or(RarimeError::ASN1RouteError(
                "Expected Application 23 SEQUENCE in the root".to_string(),
            ))?;

        let seq_in_app23 = match app23_block {
            ASN1Block::Explicit(_, _, _, content) => match content.as_ref() {
                ASN1Block::Sequence(_, inner) => inner,
                _ => {
                    return Err(RarimeError::ASN1RouteError(
                        "Expected SEQUENCE inside Application 23".to_string(),
                    ));
                }
            },
            _ => {
                return Err(RarimeError::ASN1RouteError(
                    "Expected Explicit block for Application[23]".to_string(),
                ));
            }
        };

        let tagged0_block = seq_in_app23
            .iter()
            .find(|b| matches!(b, ASN1Block::Explicit(_, _, tag, _) if *tag == BigUint::from(0u32)))
            .ok_or(RarimeError::ASN1RouteError(
                "No [0] tagged block found".to_string(),
            ))?;

        let seq_in_tagged0 = match tagged0_block {
            ASN1Block::Explicit(_, _, _, content) => match content.as_ref() {
                ASN1Block::Sequence(_, inner) => inner,
                _ => {
                    return Err(RarimeError::ASN1RouteError(
                        "Expected SEQUENCE inside [0]".to_string(),
                    ));
                }
            },
            _ => {
                return Err(RarimeError::ASN1RouteError(
                    "Expected Explicit block for [0]".to_string(),
                ));
            }
        };

        let set_block = seq_in_tagged0
            .iter()
            .find(|b| matches!(b, ASN1Block::Set(_, _)))
            .ok_or(RarimeError::ASN1RouteError(
                ("No SET found inside [0] SEQUENCE").to_string(),
            ))?;

        let inner_seq = if let ASN1Block::Set(_, content) = set_block {
            let seq = content
                .get(0)
                .ok_or(RarimeError::ASN1RouteError(("SET is empty").to_string()))?;
            match seq {
                ASN1Block::Sequence(_, _) => seq,
                _ => {
                    return Err(RarimeError::ASN1RouteError(
                        "Expected SEQUENCE as first element of SET".to_string(),
                    ));
                }
            }
        } else {
            return Err(RarimeError::ASN1RouteError(
                "Expected SET block".to_string(),
            ));
        };

        let oid_block = if let ASN1Block::Sequence(_, seq_content) = inner_seq {
            let oid = seq_content.get(0).ok_or(RarimeError::ASN1RouteError(
                ("Inner SEQUENCE is empty").to_string(),
            ))?;
            match oid {
                ASN1Block::ObjectIdentifier(_, _) => oid.clone(),
                _ => {
                    return Err(RarimeError::ASN1RouteError(
                        "Expected ObjectIdentifier as first element of inner SEQUENCE".to_string(),
                    ));
                }
            }
        } else {
            return Err(RarimeError::ASN1RouteError(
                "Expected ObjectIdentifier as first element of inner SEQUENCE".to_string(),
            ));
        };

        Ok(oid_block)
    }

    fn parse_dg15_pubkey(dg15_bytes: &[u8]) -> Result<ActiveAuthKey, RarimeError> {
        let blocks = from_der(dg15_bytes).map_err(|e| RarimeError::ASN1DecodeError(e))?;

        let seq = match &blocks[0] {
            ASN1Block::Sequence(_, inner) => inner,
            ASN1Block::Explicit(class, _, tag, content)
                if *class == ASN1Class::Application && *tag == BigUint::from(15u32) =>
            {
                match content.as_ref() {
                    ASN1Block::Sequence(_, inner2) => inner2,
                    _ => {
                        return Err(RarimeError::ASN1RouteError(
                            "Expected SEQUENCE inside Application 15".to_string(),
                        ));
                    }
                }
            }
            _ => {
                return Err(RarimeError::ASN1RouteError(
                    "Expected SEQUENCE or Application 15 for DG15".to_string(),
                ));
            }
        };

        let _algorithm = &seq[0];
        let bitstring = match &seq[1] {
            ASN1Block::BitString(_, _, bs_bytes) => bs_bytes,
            _ => {
                return Err(RarimeError::ASN1RouteError(
                    "Expected BIT STRING for subjectPublicKey".to_string(),
                ));
            }
        };

        if let Ok(inner_blocks) = from_der(bitstring)
            && let ASN1Block::Sequence(_, rsa_inner) = &inner_blocks[0]
        {
            let modulus = match &rsa_inner[0] {
                ASN1Block::Integer(_, n) => n.clone(),
                _ => {
                    return Err(RarimeError::ASN1RouteError(
                        "Expected INTEGER modulus".to_string(),
                    ));
                }
            };
            let exponent = match &rsa_inner[1] {
                ASN1Block::Integer(_, e) => e.clone(),
                _ => {
                    return Err(RarimeError::ASN1RouteError(
                        "Expected INTEGER exponent".to_string(),
                    ));
                }
            };
            return Ok(ActiveAuthKey::Rsa { modulus, exponent });
        }

        Ok(ActiveAuthKey::Ecdsa {
            key_bytes: bitstring.clone(),
        })
    }

    pub fn extract_signed_attributes(&self) -> Result<ASN1Block, RarimeError> {
        let blocks = from_der(&self.sod).map_err(|e| RarimeError::ASN1DecodeError(e))?;
        let root = blocks.first().ok_or(RarimeError::EmptyDer)?;

        let app23_seq = match root {
            ASN1Block::Explicit(class, _, tag, content)
                if *class == ASN1Class::Application && *tag == BigUint::from(23u32) =>
            {
                match content.as_ref() {
                    ASN1Block::Sequence(_, inner) => inner.clone(),
                    _other => {
                        return Err(RarimeError::ASN1RouteError(
                            "Expected SEQUENCE inside Application 23".to_string(),
                        ));
                    }
                }
            }
            _other => {
                return Err(RarimeError::ASN1RouteError(
                    "Expected Application 23 at root".to_string(),
                ));
            }
        };

        let tagged0_inner_blocks: Vec<ASN1Block> = {
            let found = app23_seq
                .iter()
                .find(|b| match b {
                    ASN1Block::Explicit(_, _, tag, _) if *tag == BigUint::from(0u32) => true,
                    ASN1Block::Unknown(_, _, _, tag, _) => format!("{:?}", tag) == "0",
                    _ => false,
                })
                .ok_or(RarimeError::ASN1RouteError(
                    "No [0] tagged block found in Application 23 SEQUENCE".to_string(),
                ))?;

            match found {
                ASN1Block::Explicit(_, _, _, content) => match content.as_ref() {
                    ASN1Block::Sequence(_, v) => v.clone(),
                    ASN1Block::Set(_, v) => v.clone(),
                    other => vec![other.clone()],
                },
                ASN1Block::Unknown(_, _, _, _tag, raw_bytes) => {
                    from_der(raw_bytes).map_err(|e| RarimeError::ASN1DecodeError(e))?
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
                if let ASN1Block::Set(_, content) = b
                    && let Some(ASN1Block::Sequence(_, inner)) = content.first()
                    && inner.len() == 6
                {
                    return Some(inner.clone());
                }
                None
            })
            .ok_or(RarimeError::ASN1RouteError(
                "No inner SET containing 6-element SEQUENCE found".to_string(),
            ))?;

        let signed_attrs_block = final_seq
            .iter()
            .find_map(|elem| {
                if let ASN1Block::Explicit(_, _, tag, content) = elem
                    && *tag == BigUint::from(0u32)
                {
                    return Some(match content.as_ref() {
                        ASN1Block::Set(_, v) => ASN1Block::Set(v.len(), v.clone()),
                        ASN1Block::Sequence(_, v) => ASN1Block::Sequence(v.len(), v.clone()),
                        other => other.clone(),
                    });
                }
                if let ASN1Block::Unknown(_, _, _, tag, raw_bytes) = elem
                    && format!("{:?}", tag) == "0"
                    && let Ok(parsed) = from_der(raw_bytes)
                {
                    return if parsed.len() == 1 {
                        Some(parsed.into_iter().next().expect("ASN1 parser returned an empty list when exactly one item was expected."))
                    } else {
                        Some(ASN1Block::Sequence(parsed.len(), parsed))
                    };
                }

                None
            })
            .ok_or(RarimeError::ASN1RouteError(
                "No [0] tag found inside final SEQUENCE".to_string(),
            ))?;

        let mut signed_attributes_der =
            to_der(&signed_attrs_block).map_err(|e| RarimeError::ASN1EncodeError(e))?;

        // Ref: RFC 5652 (CMS) section 5.4, detailing the structure's ASN.1 definition.
        signed_attributes_der[0] = 0x31;

        let redacted_signer_attributes: Vec<ASN1Block> =
            from_der(&signed_attributes_der).map_err(|e| RarimeError::ASN1DecodeError(e))?;

        Ok(redacted_signer_attributes[0].clone())
    }

    pub fn extract_encapsulated_content(&self) -> Result<ASN1Block, RarimeError> {
        let blocks = from_der(&self.sod).map_err(|e| RarimeError::ASN1DecodeError(e))?;
        let app23_block = blocks.iter().find(|b| { matches!(b, ASN1Block::Explicit(class, _, tag, _) if *class == ASN1Class::Application && *tag == BigUint::from(23u32)) }).ok_or(RarimeError::ASN1RouteError("Expected Application 23 SEQUENCE in the root".to_string()))?;
        let seq_in_app23 = match app23_block {
            ASN1Block::Explicit(_, _, _, content) => match content.as_ref() {
                ASN1Block::Sequence(_, inner) => inner,
                _ => {
                    return Err(RarimeError::ASN1RouteError(
                        "Expected SEQUENCE inside Application 23".to_string(),
                    ));
                }
            },
            _ => {
                return Err(RarimeError::ASN1RouteError(
                    "Expected Explicit block for Application[23]".to_string(),
                ));
            }
        };
        let tagged0_block = seq_in_app23
            .iter()
            .find(|b| matches!(b, ASN1Block::Explicit(_, _, tag, _) if *tag == BigUint::from(0u32)))
            .ok_or(RarimeError::ASN1RouteError(
                "No [0] tagged block found".to_string(),
            ))?;
        let inner_seq_content = match tagged0_block {
            ASN1Block::Explicit(_, _, _, content) => match content.as_ref() {
                ASN1Block::Sequence(_, inner) => inner,
                _ => {
                    return Err(RarimeError::ASN1RouteError(
                        "Expected SEQUENCE inside [0]".to_string(),
                    ));
                }
            },
            _ => {
                return Err(RarimeError::ASN1RouteError(
                    "Expected Explicit block for [0]".to_string(),
                ));
            }
        };
        let encapsulated_content_wrapper =
            inner_seq_content.get(2).ok_or(RarimeError::ASN1RouteError(
                "Expected element at index 2 (Encapsulated Content)".to_string(),
            ))?;
        let encapsulated_content_wrapper_content = match encapsulated_content_wrapper {
            ASN1Block::Sequence(_, content) => content,
            _ => {
                return Err(RarimeError::ASN1RouteError(
                    "Expected SEQUENCE inside encapsulated_content_wrapper".to_string(),
                ));
            }
        };
        let encapsulated_content_blocks = encapsulated_content_wrapper_content
            .iter()
            .find_map(|b| {
                if let ASN1Block::Explicit(_, _, tag, inner_blocks) = b {
                    if *tag == BigUint::from(0u32) {
                        Some(inner_blocks.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .ok_or(RarimeError::ASN1RouteError(
                "No encapsulated_content block found".to_string(),
            ))?;

        return Ok(*encapsulated_content_blocks.clone());
    }

    pub fn get_signature_algorithm(&self) -> Result<SignatureAlgorithm, RarimeError> {
        let passport_signature_block = self.extract_passport_signature_block()?;
        let parsed_oid = extract_oid_from_asn1(&passport_signature_block)?;
        let passport_signature = SignatureAlgorithm::from_oid(parsed_oid)?;
        return Ok(passport_signature);
    }

    fn extract_passport_signature_block(&self) -> Result<ASN1Block, RarimeError> {
        let blocks = from_der(&self.sod).map_err(|e| RarimeError::ASN1DecodeError(e))?;

        let app23_seq = match &blocks[0] {
            ASN1Block::Explicit(class, _, tag, content)
                if *class == ASN1Class::Application && *tag == BigUint::from(23u32) =>
            {
                match content.as_ref() {
                    ASN1Block::Sequence(_, inner) => inner,
                    _ => {
                        return Err(RarimeError::ASN1RouteError(
                            "Expected SEQUENCE inside Application 23".to_string(),
                        ));
                    }
                }
            }
            _ => {
                return Err(RarimeError::ASN1RouteError(
                    "Expected Application 23".to_string(),
                ));
            }
        };

        let tagged0 = app23_seq
            .iter()
            .find_map(|b| {
                if let ASN1Block::Explicit(_, _, tag, content) = b
                    && *tag == BigUint::from(0u32)
                {
                    return Some(content.as_ref());
                }
                None
            })
            .ok_or(RarimeError::ASN1RouteError(
                "No [0] tagged block found in Application 23 SEQUENCE".to_string(),
            ))?;

        let inner_seq = match tagged0 {
            ASN1Block::Sequence(_, inner) => inner,
            _ => {
                return Err(RarimeError::ASN1RouteError(
                    "Expected SEQUENCE inside [0]".to_string(),
                ));
            }
        };

        let sequence_block = inner_seq
            .iter()
            .find_map(|b| {
                if let ASN1Block::Set(_, content) = b
                    && let Some(ASN1Block::Sequence(_, inner)) = content.first()
                    && inner.len() == 6
                {
                    return Some(inner.clone());
                }
                None
            })
            .ok_or(RarimeError::ASN1RouteError(
                "No inner SET containing 6-element SEQUENCE found".to_string(),
            ))?;

        let sig_alg_block = sequence_block
            .iter()
            .find_map(|b| {
                if let ASN1Block::Sequence(_, inner) = b
                    && let ASN1Block::ObjectIdentifier(tag, oid) = &inner[0]
                {
                    let oid_string = oid
                        .as_vec::<&BigUint>()
                        .ok()?
                        .iter()
                        .map(|n| n.to_string())
                        .collect::<Vec<_>>()
                        .join(".");

                    if oid_string.starts_with("1.2.840.".to_string().as_str()) {
                        return Some(ASN1Block::ObjectIdentifier(*tag, oid.clone()));
                    }
                }
                None
            })
            .ok_or(RarimeError::ASN1RouteError(
                "No signature algorithm OID found".to_string(),
            ))?;

        Ok(sig_alg_block)
    }

    pub fn get_certificate_pem(&self) -> Result<String, RarimeError> {
        let extracted_certificate_block = self.extract_certificate()?;
        let pem_certificate = convert_asn1_to_pem(&extracted_certificate_block)?;

        return Ok(pem_certificate);
    }

    pub fn extract_certificate(&self) -> Result<ASN1Block, RarimeError> {
        let blocks = from_der(&self.sod).map_err(|e| RarimeError::ASN1DecodeError(e))?;

        let app23_seq = match &blocks[0] {
            ASN1Block::Explicit(class, _, tag, content)
                if *class == ASN1Class::Application && *tag == BigUint::from(23u32) =>
            {
                match content.as_ref() {
                    ASN1Block::Sequence(_, inner) => inner,
                    _ => {
                        return Err(RarimeError::ASN1RouteError(
                            "Expected SEQUENCE inside Application 23".to_string(),
                        ));
                    }
                }
            }
            _ => {
                return Err(RarimeError::ASN1RouteError(
                    "Expected Application 23".to_string(),
                ));
            }
        };

        let tagged0 = app23_seq
            .iter()
            .find_map(|b| {
                if let ASN1Block::Explicit(_, _, tag, content) = b
                    && *tag == BigUint::from(0u32)
                {
                    return Some(content.as_ref());
                }
                None
            })
            .ok_or(RarimeError::ASN1RouteError(
                "No [0] tagged block found in Application 23 SEQUENCE".to_string(),
            ))?;

        let inner_seq = match tagged0 {
            ASN1Block::Sequence(_, inner) => inner,
            _ => {
                return Err(RarimeError::ASN1RouteError(
                    "Expected SEQUENCE inside [0]".to_string(),
                ));
            }
        };
        let tagged0_ref = inner_seq
            .iter()
            .find_map(|b| {
                if let ASN1Block::Explicit(_, _, tag, _) = b
                    && *tag == BigUint::from(0u32)
                {
                    return Some(b);
                }
                None
            })
            .ok_or_else(|| {
                RarimeError::ASN1RouteError("No [0] tagged block found in SEQUENCE".to_string())
            })?;

        let inner_seq_block = match tagged0_ref {
            ASN1Block::Explicit(_, _, _, content_box) => {
                let inner_block = content_box.as_ref();
                match inner_block {
                    ASN1Block::Sequence(_, _) => inner_block.clone(),
                    _ => {
                        return Err(RarimeError::ASN1RouteError(
                            "Expected SEQUENCE inside [0]".to_string(),
                        ));
                    }
                }
            }
            _ => {
                return Err(RarimeError::ASN1RouteError(
                    "Internal logic error: Expected Explicit block".to_string(),
                ));
            }
        };
        Ok(inner_seq_block.clone())
    }

    pub fn prove_dg1(&self, private_key: &[u8; 32]) -> Result<Vec<u8>, RarimeError> {
        let dg_algo_block = &self.extract_dg_hash_algo_block()?;

        let parsed_oid = extract_oid_from_asn1(&dg_algo_block)?;
        let parsed_hash_algorithm = HashAlgorithm::from_oid(parsed_oid)?;
        let proof_inputs = LiteRegisterProofInput {
            dg1: self.data_group1.clone(),
            sk: BigUint::from_bytes_be(private_key).to_str_radix(10),
        };

        let proof_provider = ProofProvider::new();
        let register_proof = proof_provider
            .generate_lite_proof(parsed_hash_algorithm.get_byte_length(), proof_inputs)?;

        return Ok(register_proof);
    }

    pub async fn generate_document_query_proof(
        &self,
        params: QueryProofParams,
        passport_key: &[u8; 32],
        pk_key: &[u8; 32],
        config: ContractsProviderConfig,
    ) -> Result<Vec<u8>, RarimeError> {
        let contacts = ContractsProvider::new(config);

        let utils = RarimeUtils::new();

        let profile_key = vec_u8_to_u8_32(&utils.get_profile_key(pk_key.to_vec())?)?;

        let passport_info = contacts.get_passport_info(&passport_key).await?;

        if (profile_key != passport_info.passportInfo_.activeIdentity) {
            return Err(RarimeError::ProfileKeyError(format!(
                "profile key mismatch. profile_key = {},   passport_info.passportInfo_.activeIdentity= {}",
                hex::encode(profile_key),
                hex::encode(passport_info.passportInfo_.activeIdentity)
            )));
        }

        let smt_proof_index = get_smt_proof_index(&passport_key, &profile_key)?;

        let smt_proof = contacts.get_smt_proof(&smt_proof_index).await?;

        let now_time = Utc::now();

        let proof_inputs = QueryProofInput {
            event_id: params.event_id, //from input
            event_data: BigUint::from_bytes_be(&hex::decode(
                params.event_data.chars().skip(2).collect::<String>(),
            )?)
            .to_str_radix(10),
            id_state_root: BigUint::from_bytes_be(smt_proof.root.as_slice()).to_str_radix(10), //from SMT
            selector: params.selector, //from input
            current_date: format!("0x{}", hex::encode(now_time.format("%y%m%d").to_string())),
            timestamp_lowerbound: params.timestamp_lowerbound, //from input
            timestamp_upperbound: params.timestamp_upperbound, //from input
            identity_count_lowerbound: params.identity_count_lowerbound, //from input
            identity_count_upperbound: params.identity_count_upperbound, //from input
            birth_date_lowerbound: params.birth_date_lowerbound, //from input
            birth_date_upperbound: params.birth_date_upperbound, //from input
            expiration_date_lowerbound: params.expiration_date_lowerbound, //from input
            expiration_date_upperbound: params.expiration_date_upperbound, //from input
            citizenship_mask: params.citizenship_mask,         //from input
            sk_identity: BigUint::from_bytes_be(pk_key).to_str_radix(10),
            pk_passport_hash: BigUint::from_bytes_be(&self.get_passport_key()?).to_str_radix(10),
            dg1: self.data_group1.clone(),
            siblings: smt_proof
                .siblings
                .iter()
                .map(|block| BigUint::from_bytes_be(block.as_slice()).to_str_radix(10))
                .collect(), //from SMT
            timestamp: passport_info.identityInfo_.issueTimestamp.to_string(),
            identity_counter: passport_info
                .passportInfo_
                .identityReissueCounter
                .to_string(),
        };

        let proof_provider = ProofProvider::new();
        let query_proof = proof_provider.generate_query_proof(proof_inputs)?;

        return Ok(query_proof);
    }
}
