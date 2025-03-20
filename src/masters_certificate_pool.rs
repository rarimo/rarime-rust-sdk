use digest::Digest;
use num_bigint_dig::BigUint;

use crate::{
    RarimeError,
    rfc::{self, rfc5280},
};

pub struct MastersCertificatePool<'a> {
    pub masters: Vec<rfc5280::Certificate<'a>>,
}

impl<'a> MastersCertificatePool<'a> {
    pub fn new() -> Self {
        Self { masters: vec![] }
    }

    pub fn add_masters(&mut self, mut certificates_to_add: Vec<rfc5280::Certificate<'a>>) {
        self.masters.append(&mut certificates_to_add);
    }

    pub fn find_master(&self, slave: rfc5280::Certificate<'a>) {
        let signature_algorithm = slave.signature_algorithm.algorithm;
        let signature = hex::encode(slave.signature_value.as_bytes());

        println!("signature_algorithm: {signature_algorithm}");
        println!("signature: {signature}");
    }

    fn check_rsa(
        slave: rfc5280::Certificate<'a>,
        master: rfc5280::Certificate<'a>,
    ) -> Result<bool, RarimeError> {
        let x509_rsa_public_key = master
            .tbs_certificate
            .subject_public_key_info
            .get_rsa_public_key()?;
        let x509_rsa_public_key_n = BigUint::from_bytes_be(x509_rsa_public_key.modulus.as_bytes());
        let x509_rsa_public_key_e =
            BigUint::from_bytes_be(&x509_rsa_public_key.exponent.to_be_bytes());

        let master_public_key =
            rsa::RsaPublicKey::new(x509_rsa_public_key_n, x509_rsa_public_key_e)?;

        // master_public_key.verify(
        //     rsa::pkcs1v15::Pkcs1v15Sign::new(),
        //     hashed,
        //     slave.signature_value.as_bytes(),
        // );

        Ok(false)
    }

    fn hash_certificate(slave: rfc5280::Certificate<'a>) {
        let to_hash_data = slave.signature_value.as_bytes();

        let mut hash: Vec<u8> = vec![];
        match slave.signature_algorithm.algorithm {
            rfc::RSA_WITH_SHA1 | rfc::ECDSA_WITH_SHA1 => {
                let mut hasher = sha1::Sha1::new();
                hasher.update(to_hash_data);
                let output = hasher.finalize();
            }
            rfc::RSA_WITH_SHA256 | rfc::ECDSA_WITH_SHA256 => {
                let mut hasher = sha2::Sha256::new();
                hasher.update(to_hash_data);
                let output = hasher.finalize();
            }
            rfc::RSA_WITH_SHA384 | rfc::ECDSA_WITH_SHA384 => {
                let mut hasher = sha2::Sha384::new();
                hasher.update(to_hash_data);
                let output = hasher.finalize();
            }
            rfc::RSA_WITH_SHA512 | rfc::ECDSA_WITH_SHA512 => {
                let mut hasher = sha2::Sha512::new();
                hasher.update(to_hash_data);
                let output = hasher.finalize();
            }
            _ => {}
        }
    }
}
