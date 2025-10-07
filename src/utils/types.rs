use serde::Serialize;

#[derive(Serialize, Debug)]
pub struct Proof {
    pub proof: Vec<u8>,
}

#[derive(Serialize, Debug)]
pub struct ZkProof {
    pub proof: Proof,
}

#[derive(Serialize, Debug)]
pub struct DocumentSod {
    pub hash_algorithm: String,
    pub signature_algorithm: String,
    pub signed_attributes: String,
    pub encapsulated_content: String,
    pub signature: String,
    pub aa_signature: String,
    pub pem_file: String,
    pub dg15: String,
}

#[derive(Serialize, Debug)]
pub struct Attributes {
    pub document_sod: DocumentSod,
    pub zk_proof: ZkProof,
}

#[derive(Serialize, Debug)]
pub struct Data {
    pub attributes: Attributes,
}

#[derive(Serialize, Debug)]
pub struct PostRequest {
    pub data: Data,
}
