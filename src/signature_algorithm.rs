use crate::RarimeError;
use const_oid::ObjectIdentifier;
use const_oid::db::rfc5912::{
    ECDSA_WITH_SHA_224, ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ECDSA_WITH_SHA_512, ID_RSASSA_PSS,
    SHA_1_WITH_RSA_ENCRYPTION, SHA_224_WITH_RSA_ENCRYPTION, SHA_256_WITH_RSA_ENCRYPTION,
    SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
};

#[derive(Debug)]
pub enum SignatureAlgorithm {
    RSA,
    RsaPss,
    ECDSA,
}

impl SignatureAlgorithm {
    pub fn to_string(&self) -> String {
        let string = match self {
            SignatureAlgorithm::RSA => "RSA".to_string(),
            SignatureAlgorithm::RsaPss => "RSA-PSS".to_string(),
            SignatureAlgorithm::ECDSA => "ECDSA".to_string(),
        };

        return string;
    }

    pub fn from_oid(oid: ObjectIdentifier) -> Result<SignatureAlgorithm, RarimeError> {
        match oid {
            SHA_1_WITH_RSA_ENCRYPTION
            | SHA_224_WITH_RSA_ENCRYPTION
            | SHA_256_WITH_RSA_ENCRYPTION
            | SHA_384_WITH_RSA_ENCRYPTION
            | SHA_512_WITH_RSA_ENCRYPTION => Ok(SignatureAlgorithm::RSA),

            ID_RSASSA_PSS => Ok(SignatureAlgorithm::RsaPss),

            ECDSA_WITH_SHA_224 | ECDSA_WITH_SHA_256 | ECDSA_WITH_SHA_384 | ECDSA_WITH_SHA_512 => {
                Ok(SignatureAlgorithm::ECDSA)
            }
            _ => Err(RarimeError::ASN1RouteError(format!(
                "Not supported ObjectIdentifier for signature algorithm: {}",
                oid
            ))),
        }
    }
}
