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

    pub fn find_master(
        &self,
        slave: &rfc5280::Certificate<'a>,
    ) -> Result<Option<&rfc5280::Certificate<'a>>, RarimeError> {
        for master in &self.masters {
            if slave.signature_algorithm.get_signature_type()
                != master
                    .tbs_certificate
                    .subject_public_key_info
                    .algorithm
                    .get_signature_type()
            {
                continue;
            }

            match slave.signature_algorithm.algorithm {
                rfc::RSA_WITH_SHA1
                | rfc::RSA_WITH_SHA256
                | rfc::RSA_WITH_SHA384
                | rfc::RSA_WITH_SHA512 => {
                    if Self::check_rsa(slave, master)? {
                        return Ok(Some(master));
                    }
                }
                rfc::ECDSA_WITH_SHA1
                | rfc::ECDSA_WITH_SHA256
                | rfc::ECDSA_WITH_SHA384
                | rfc::ECDSA_WITH_SHA512 => {
                    if Self::check_ecdsa(slave, master)? {
                        return Ok(Some(master));
                    }
                }
                _ => {}
            }
        }

        return Ok(None);
    }

    fn check_rsa(
        slave: &rfc5280::Certificate<'a>,
        master: &rfc5280::Certificate<'a>,
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

        let hasher = Self::get_pkcs1v15_hasher(&slave.signature_algorithm.algorithm)
            .ok_or(RarimeError::UnsupportedSignatureAlgorithm)?;

        let hashed = Self::hash_certificate(slave)?;

        match master_public_key.verify(hasher, &hashed, slave.signature_value.as_bytes()) {
            Ok(_) => return Ok(true),
            Err(_) => return Ok(false),
        }
    }

    #[allow(unused_variables)]
    fn check_ecdsa(
        slave: &rfc5280::Certificate<'a>,
        master: &rfc5280::Certificate<'a>,
    ) -> Result<bool, RarimeError> {
        Ok(false)
    }

    fn get_pkcs1v15_hasher(
        hash_id: &asn1::ObjectIdentifier,
    ) -> Option<rsa::pkcs1v15::Pkcs1v15Sign> {
        match *hash_id {
            rfc::RSA_WITH_SHA1 | rfc::ECDSA_WITH_SHA1 => {
                Some(rsa::pkcs1v15::Pkcs1v15Sign::new::<sha1::Sha1>())
            }
            rfc::RSA_WITH_SHA256 | rfc::ECDSA_WITH_SHA256 => {
                Some(rsa::pkcs1v15::Pkcs1v15Sign::new::<sha2::Sha256>())
            }
            rfc::RSA_WITH_SHA384 | rfc::ECDSA_WITH_SHA384 => {
                Some(rsa::pkcs1v15::Pkcs1v15Sign::new::<sha2::Sha384>())
            }
            rfc::RSA_WITH_SHA512 | rfc::ECDSA_WITH_SHA512 => {
                Some(rsa::pkcs1v15::Pkcs1v15Sign::new::<sha2::Sha512>())
            }
            _ => None,
        }
    }

    fn hash_certificate(slave: &rfc5280::Certificate<'a>) -> Result<Vec<u8>, RarimeError> {
        let to_hash_data = asn1::write_single(&slave.tbs_certificate)?;

        let hash = match slave.signature_algorithm.algorithm {
            rfc::RSA_WITH_SHA1 | rfc::ECDSA_WITH_SHA1 => sha1::Sha1::digest(to_hash_data).to_vec(),
            rfc::RSA_WITH_SHA256 | rfc::ECDSA_WITH_SHA256 => {
                sha2::Sha256::digest(to_hash_data).to_vec()
            }
            rfc::RSA_WITH_SHA384 | rfc::ECDSA_WITH_SHA384 => {
                sha2::Sha384::digest(to_hash_data).to_vec()
            }
            rfc::RSA_WITH_SHA512 | rfc::ECDSA_WITH_SHA512 => {
                sha2::Sha512::digest(to_hash_data).to_vec()
            }
            _ => vec![],
        };

        Ok(hash)
    }
}
