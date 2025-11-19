use crate::RarimeError;
use crate::RarimeError::PoseidonHashError;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use const_oid::ObjectIdentifier;
use ff::{PrimeField, PrimeFieldRepr};
use num_bigint::{BigInt, Sign};
use num_traits::Zero;
use poseidon_rs::{Fr, FrRepr};
use simple_asn1::{ASN1Block, to_der};
use std::io::Cursor;

pub fn big_int_to_32_bytes(num: &BigInt) -> [u8; 32] {
    let mut out = [0u8; 32];

    if num.is_zero() {
        return out;
    }

    let num_bytes = num.to_signed_bytes_be();
    let len = num_bytes.len();

    if len > 32 {
        out.copy_from_slice(&num_bytes[len - 32..]);
    } else {
        let start_index = 32 - len;
        out[start_index..].copy_from_slice(&num_bytes);
    }
    out
}

pub fn poseidon_hash_32_bytes(vec_big_int: &[BigInt]) -> Result<[u8; 32], RarimeError> {
    let poseidon = poseidon_rs::Poseidon::new();
    let vec_fr: Result<Vec<Fr>, RarimeError> = vec_big_int
        .iter()
        .map(|big_int| -> Result<Fr, RarimeError> {
            let bytes = big_int_to_32_bytes(big_int);
            let mut repr = FrRepr::default();
            let mut cursor = Cursor::new(&bytes);

            repr.read_be(&mut cursor).map_err(|e| {
                RarimeError::PrimeFieldConvertingError(format!("Error convert BigInt to Fr: {}", e))
            })?;

            let fr = Fr::from_repr(repr).map_err(|e| {
                RarimeError::PrimeFieldConvertingError(format!(
                    "Error converting Repr to Fr: {}",
                    e
                ))
            })?;

            Ok(fr)
        })
        .collect();

    let vec_fr = vec_fr?;
    let hash_result: Fr = poseidon.hash(vec_fr).map_err(PoseidonHashError)?;

    let repr = hash_result.into_repr();

    let mut raw_hash_bytes = Vec::new();

    repr.write_be(&mut raw_hash_bytes).map_err(|e| {
        RarimeError::PrimeFieldConvertingError(format!("Error converting repr to byte: {}", e))
    })?;

    let result_big_int = BigInt::from_bytes_be(Sign::Plus, &raw_hash_bytes);

    let big_int_32_bytes = big_int_to_32_bytes(&result_big_int);

    Ok(big_int_32_bytes)
}

pub fn extract_oid_from_asn1(oid_block: &ASN1Block) -> Result<ObjectIdentifier, RarimeError> {
    let oid: ObjectIdentifier = if let ASN1Block::ObjectIdentifier(_, raw_oid) = oid_block {
        ObjectIdentifier::from_bytes(
            &raw_oid
                .as_raw()
                .map_err(|e| RarimeError::ASN1EncodeError(e))?,
        )
        .map_err(|e| RarimeError::OIDError(e))?
    } else {
        return Err(RarimeError::ASN1RouteError(
            "Expected ObjectIdentifier block".to_string(),
        ));
    };
    return Ok(oid);
}

pub fn convert_asn1_to_pem(asn1_block: &ASN1Block) -> Result<String, RarimeError> {
    let der_bytes = to_der(asn1_block).map_err(|e| RarimeError::ASN1EncodeError(e))?;

    let base64_content = STANDARD.encode(der_bytes);

    let pem_header = "-----BEGIN CERTIFICATE-----\n";
    let pem_footer = "\n-----END CERTIFICATE-----";

    let formatted_base64 = base64_content
        .as_bytes()
        .chunks(64)
        .map(|chunk| format!("{}\n", String::from_utf8_lossy(chunk)))
        .collect::<String>();

    let pem_string = format!("{}{}{}", pem_header, formatted_base64, pem_footer);

    Ok(pem_string)
}

pub fn vec_u8_to_u8_32(vec: &Vec<u8>) -> Result<[u8; 32], RarimeError> {
    let result: [u8; 32] = vec.as_slice().try_into().map_err(|_| {
        RarimeError::VectorSizeValidationError("Vector must be 32 bytes in length.".to_string())
    })?;
    return Ok(result);
}

pub fn get_smt_proof_index(
    passport_key: &[u8; 32],
    profile_key: &[u8; 32],
) -> Result<[u8; 32], RarimeError> {
    let passport_key_big_int = BigInt::from_bytes_be(Sign::Plus, passport_key);
    let profile_key_big_int = BigInt::from_bytes_be(Sign::Plus, profile_key);

    let result = poseidon_hash_32_bytes(&[passport_key_big_int, profile_key_big_int])?;

    return Ok(result);
}
