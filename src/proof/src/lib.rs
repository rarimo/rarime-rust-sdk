mod register_proof;
mod utils;

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
}
