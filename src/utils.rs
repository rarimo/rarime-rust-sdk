use crate::RarimeError;
use crate::RarimeError::PoseidonHashError;
use const_oid::ObjectIdentifier;
use ff::{PrimeField, PrimeFieldRepr};
use num_bigint::BigInt;
use num_traits::Zero;
use poseidon_rs::{Fr, FrRepr};
use simple_asn1::ASN1Block;
use std::io::Cursor;

pub mod rarime_utils {
    use crate::RarimeError;
    use babyjubjub_rs::new_key;

    // GenerateBJJSecretKey generates a new secret key for the Baby JubJub curve.
    pub fn generate_bjj_private_key() -> Result<[u8; 32], RarimeError> {
        let private_key = new_key();
        let scalar = private_key.scalar_key();
        let (_, scalar_bytes) = scalar.to_bytes_be();

        let fixed_bytes: [u8; 32] = scalar_bytes
            .try_into()
            .map_err(|_| RarimeError::GeneratePrivateKeyError)?;

        Ok(fixed_bytes)
    }
}

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
    let vec_fr: Vec<Fr> = vec_big_int
        .iter()
        .map(|big_int| {
            let bytes = big_int_to_32_bytes(big_int);

            let mut repr = FrRepr::default();

            let mut cursor = Cursor::new(&bytes);
            repr.read_be(&mut cursor)
                .expect("error convert BigInt to Fr ");

            Fr::from_repr(repr).expect("error converting Repr to Fr")
        })
        .collect();
    let hash_result: Fr = poseidon.hash(vec_fr).map_err(PoseidonHashError)?;

    let repr = hash_result.into_repr();

    let mut raw_hash_bytes = Vec::new();

    repr.write_be(&mut raw_hash_bytes)
        .expect("Error converting repr to bytes");

    let result_big_int = BigInt::from_bytes_be(num_bigint::Sign::Plus, &raw_hash_bytes);

    let big_int_32 = big_int_to_32_bytes(&result_big_int);

    Ok(big_int_32)
}

pub fn get_profile_key(private_key: &[u8; 32]) -> Result<[u8; 32], RarimeError> {
    let scalar_int = BigInt::from_bytes_be(num_bigint::Sign::Plus, private_key);

    let b8 = babyjubjub_rs::Point {
        x: babyjubjub_rs::Fr::from_str(
            "5299619240641551281634865583518297030282874472190772894086521144482721001553",
        )
        .expect("Failed to init Generator point"),
        y: babyjubjub_rs::Fr::from_str(
            "16950150798460657717958625567821834550301663161624707787222815936182638968203",
        )
        .expect("Failed to init Generator point"),
    };
    let pub_point = b8.mul_scalar(&scalar_int);
    let mut x_raw_bytes = Vec::new();
    let x_raw = pub_point.x.into_repr();
    x_raw
        .write_be(&mut x_raw_bytes)
        .expect("Error converting repr to bytes");
    let x_big_int = BigInt::from_bytes_be(num_bigint::Sign::Plus, &x_raw_bytes);

    let mut y_raw_bytes = Vec::new();
    let y_raw = pub_point.y.into_repr();
    y_raw
        .write_be(&mut y_raw_bytes)
        .expect("Error converting repr to bytes");
    let y_big_int = BigInt::from_bytes_be(num_bigint::Sign::Plus, &y_raw_bytes);

    let profile_key = poseidon_hash_32_bytes(&vec![x_big_int, y_big_int])?;
    Ok(profile_key)
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
