use crate::RarimeError;
use const_oid::ObjectIdentifier;
use const_oid::db::rfc5912::{
    ECDSA_WITH_SHA_224, ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ECDSA_WITH_SHA_512, ID_SHA_1,
    ID_SHA_224, ID_SHA_256, ID_SHA_384, ID_SHA_512, SHA_1_WITH_RSA_ENCRYPTION,
    SHA_224_WITH_RSA_ENCRYPTION, SHA_256_WITH_RSA_ENCRYPTION, SHA_384_WITH_RSA_ENCRYPTION,
    SHA_512_WITH_RSA_ENCRYPTION,
};
use digest::Digest;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};

#[derive(Debug)]
pub enum HashAlgorithm {
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
}

impl HashAlgorithm {
    pub fn get_byte_length(&self) -> usize {
        match self {
            HashAlgorithm::SHA1 => 160,
            HashAlgorithm::SHA224 => 224,
            HashAlgorithm::SHA256 => 256,
            HashAlgorithm::SHA384 => 384,
            HashAlgorithm::SHA512 => 512,
        }
    }

    pub fn get_hash_fixed32(&self, data_bytes: &[u8]) -> [u8; 32] {
        let digest = match self {
            HashAlgorithm::SHA1 => Sha1::digest(data_bytes).to_vec(),
            HashAlgorithm::SHA224 => Sha224::digest(data_bytes).to_vec(),
            HashAlgorithm::SHA256 => Sha256::digest(data_bytes).to_vec(),
            HashAlgorithm::SHA384 => Sha384::digest(data_bytes).to_vec(),
            HashAlgorithm::SHA512 => Sha512::digest(data_bytes).to_vec(),
        };

        let mut padded_hash = [0u8; 32];
        let len = std::cmp::min(digest.len(), 32);
        padded_hash[..len].copy_from_slice(&digest[..len]);
        return padded_hash;
    }

    pub fn to_string(&self) -> String {
        let string = match self {
            HashAlgorithm::SHA1 => "SHA1".to_string(),
            HashAlgorithm::SHA224 => "SHA224".to_string(),
            HashAlgorithm::SHA256 => "SHA256".to_string(),
            HashAlgorithm::SHA384 => "SHA384".to_string(),
            HashAlgorithm::SHA512 => "SHA512".to_string(),
        };

        return string;
    }

    pub fn from_oid(oid: ObjectIdentifier) -> Result<HashAlgorithm, RarimeError> {
        match oid {
            ID_SHA_1 | SHA_1_WITH_RSA_ENCRYPTION => Ok(HashAlgorithm::SHA1),
            ID_SHA_224 | SHA_224_WITH_RSA_ENCRYPTION | ECDSA_WITH_SHA_224 => {
                Ok(HashAlgorithm::SHA224)
            }
            ID_SHA_256 | SHA_256_WITH_RSA_ENCRYPTION | ECDSA_WITH_SHA_256 => {
                Ok(HashAlgorithm::SHA256)
            }
            ID_SHA_384 | SHA_384_WITH_RSA_ENCRYPTION | ECDSA_WITH_SHA_384 => {
                Ok(HashAlgorithm::SHA384)
            }
            ID_SHA_512 | SHA_512_WITH_RSA_ENCRYPTION | ECDSA_WITH_SHA_512 => {
                Ok(HashAlgorithm::SHA512)
            }
            _ => Err(RarimeError::ASN1RouteError(format!(
                "Not supported ObjectIdentifier for hash algorithm: {}",
                oid
            ))),
        }
    }
}
