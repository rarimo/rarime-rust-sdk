use crate::RarimeError;
use crate::RarimeError::PoseidonHashError;
use crate::hash_algorithm::HashAlgorithm;
use crate::signature_algorithm::SignatureAlgorithm;
use crate::utils::{big_int_to_32_bytes, extract_oid_from_asn1, poseidon_hash_32_bytes};
use contracts::{ContractsProvider, ContractsProviderConfig};
use ff::{PrimeField, PrimeFieldRepr};
use num_bigint::BigInt;
use num_traits::{One, Zero};
use poseidon_rs::{Fr, Poseidon};
use proofs::{LiteProofInput, ProofProvider};
use simple_asn1::{ASN1Block, ASN1Class, BigUint, from_der, to_der};
use std::io::Cursor;

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

    /// Extracts and computes a cryptographic commitment from `data_group1`
    /// using the provided secret identity key `sk_identity`.
    ///
    /// # Description
    /// This function performs the following steps:
    /// 1. Splits the binary data in `data_group1` into 4 chunks.
    /// 2. Each chunk is interpreted as a large integer (`BigInt`) built bit by bit.
    /// 3. Each of these four big integers is converted into a field element.
    /// 4. The `sk_identity` (32-byte private key) is also converted into an `Fr` element.
    /// 5. The private key is hashed using the Poseidon hash function, and the resulting field element
    ///    is appended to the list of field elements.
    /// 6. All collected field elements are then hashed again using Poseidon to produce the final commitment.
    /// 7. The resulting field element is converted back into a 32-byte array and returned.
    ///
    pub fn extract_dg1_commitment(&self, sk_identity: &[u8; 32]) -> Result<[u8; 32], RarimeError> {
        let chunk_len = &self.data_group1.len() * 2;
        let mut vec_fr = vec![];

        for i in 0..4 {
            let start_bit = i * chunk_len;
            let mut chunk = BigInt::from(0u64);
            let mut current = BigInt::from(1u64);
            let two = BigInt::from(2u64);

            for bit_pos in 0..chunk_len {
                let global_bit_idx = start_bit + bit_pos;
                let byte_idx = global_bit_idx / 8;
                let bit_in_byte = global_bit_idx % 8;
                let byte = &self.data_group1[byte_idx];
                let bit_is_set = ((byte >> bit_in_byte) & 1) != 0;
                if bit_is_set {
                    let tmp = current.clone();
                    chunk += tmp;
                }
                // current *= 2
                let mut new_current = current;
                new_current *= two.clone();
                current = new_current;
            }
            let bytes = big_int_to_32_bytes(&chunk);
            let mut repr = poseidon_rs::FrRepr::default();

            let mut cursor = Cursor::new(&bytes);
            repr.read_be(&mut cursor)
                .expect("error convert BigInt to Fr ");
            vec_fr.push(Fr::from_repr(repr).expect("error converting repr to Fr"));
        }

        let mut repr = poseidon_rs::FrRepr::default();

        let mut cursor = Cursor::new(&sk_identity);
        repr.read_be(&mut cursor)
            .expect("error convert BigInt to Fr ");

        let sk_fr = Fr::from_repr(repr).expect("error converting Repr to Fr");

        let poseidon_hasher = Poseidon::new();

        let inner = poseidon_hasher
            .hash(vec![sk_fr])
            .map_err(PoseidonHashError)?;
        vec_fr.push(inner);

        let hash_result: Fr = poseidon_hasher.hash(vec_fr).map_err(PoseidonHashError)?;

        let repr = hash_result.into_repr();

        let mut raw_hash_bytes = Vec::new();

        repr.write_be(&mut raw_hash_bytes)
            .expect("Error converting repr to bytes");

        let result_big_int = BigInt::from_bytes_be(num_bigint::Sign::Plus, &raw_hash_bytes);

        let big_int_32 = big_int_to_32_bytes(&result_big_int);

        return Ok(big_int_32);
    }

    fn get_passport_hash(&self) -> Result<[u8; 32], RarimeError> {
        let sign_attr: ASN1Block = self.extract_signed_attributes()?;

        let hash_block = RarimePassport::extract_passport_signature_block(&self)?;
        let parsed_oid = extract_oid_from_asn1(&hash_block)?;
        let parsed_hash_algorithm = HashAlgorithm::from_oid(parsed_oid)?;

        let mut sign_attr_bytes =
            to_der(&sign_attr).map_err(|e| RarimeError::DerError(e.to_string()))?;

        // Ref: RFC 5652 (CMS) section 5.4, detailing the structure's ASN.1 definition.
        sign_attr_bytes[0] = 0x31;

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

    pub fn extract_dg_hash_algo(&self) -> Result<ASN1Block, RarimeError> {
        let sod_bytes = &self.sod;
        let blocks = from_der(sod_bytes).map_err(|e| RarimeError::DerError(e.to_string()))?;

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
        let blocks = from_der(dg15_bytes).map_err(|e| RarimeError::DerError(e.to_string()))?;

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
        let blocks = from_der(&self.sod).map_err(|e| RarimeError::DerError(e.to_string()))?;
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
                    from_der(raw_bytes).map_err(|e| RarimeError::DerError(e.to_string()))?
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
        Ok(signed_attrs_block)
    }

    pub fn get_signature_algorithm(&self) -> Result<SignatureAlgorithm, RarimeError> {
        let passport_signature_block = self.extract_passport_signature_block()?;
        let parsed_oid = extract_oid_from_asn1(&passport_signature_block)?;

        let passport_signature = SignatureAlgorithm::from_oid(parsed_oid)?;
        return Ok(passport_signature);
    }

    fn extract_passport_signature_block(&self) -> Result<ASN1Block, RarimeError> {
        let blocks = from_der(&self.sod).map_err(|e| RarimeError::DerError(e.to_string()))?;

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
                    && inner.len() == 2
                    && let ASN1Block::ObjectIdentifier(tag, oid) = &inner[0]
                {
                    let oid_string = oid
                        .as_vec::<&BigUint>()
                        .ok()?
                        .iter()
                        .map(|n| n.to_string())
                        .collect::<Vec<_>>()
                        .join(".");

                    return Some(ASN1Block::ObjectIdentifier(*tag, oid.clone()));
                }
                None
            })
            .ok_or(RarimeError::ASN1RouteError(
                "No RSA+SHA signature algorithm OID found".to_string(),
            ))?;

        Ok(sig_alg_block)
    }

    pub fn extract_encapsulated_content(&self) -> Result<ASN1Block, RarimeError> {
        let blocks = from_der(&self.sod).map_err(|e| RarimeError::DerError(e.to_string()))?;

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
                    "Expected SEQUENCE inside [0]".to_string(),
                ));
            }
            _ => {
                return Err(RarimeError::ASN1RouteError(
                    "Expected SEQUENCE inside [0]".to_string(),
                ));
            }
        };

        let encapsulated_content = encapsulated_content_wrapper_content
            .iter()
            .find(|b| matches!(b, ASN1Block::Explicit(_, _, tag, _) if *tag == BigUint::from(0u32)))
            .ok_or(RarimeError::ASN1RouteError(
                "No [0] tagged block found".to_string(),
            ))?;

        return Ok(encapsulated_content.clone());
    }

    pub fn prove_dg1(&self, profile_key: &[u8; 32]) -> Result<Vec<u8>, RarimeError> {
        let dg_algo_block = &self.extract_dg_hash_algo()?;

        let parsed_oid = extract_oid_from_asn1(&dg_algo_block)?;
        let parsed_hash_algorithm = HashAlgorithm::from_oid(parsed_oid)?;

        let proof_inputs = LiteProofInput {
            dg1_commitment: Vec::from(self.extract_dg1_commitment(profile_key)?),
            dg1_hash: Vec::from(parsed_hash_algorithm.get_hash_fixed32(&self.data_group1)),
            profile_key: Vec::from(profile_key),
        };

        let proof_provider =
            ProofProvider::new(proof_inputs, parsed_hash_algorithm.get_byte_length());
        let register_proof = proof_provider.generate_lite_proof()?;
        return Ok(register_proof);
    }
}
