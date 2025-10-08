use serde::{Deserialize, Serialize};

//request types

#[derive(Serialize, Debug)]
pub struct ZkProof {
    pub proof: Vec<u8>,
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
    pub sod: String,
}

#[derive(Serialize, Debug)]
pub struct Attributes {
    pub document_sod: DocumentSod,
    pub zk_proof: ZkProof,
}

#[derive(Serialize, Debug)]
pub struct Data {
    pub id: String,
    #[serde(rename = "type")]
    pub type_name: String,
    pub attributes: Attributes,
}

#[derive(Serialize, Debug)]
pub struct VerifySodRequest {
    pub data: Data,
}

//response types

#[derive(Deserialize, Debug)]
pub struct LightRegistrationData {
    pub passport_hash: String,
    pub public_key: String,
    pub signature: String,
    pub verifier: String,
}

#[derive(Deserialize, Debug)]
pub struct VerifySodResponseData {
    pub id: String,
    #[serde(rename = "type")]
    pub type_name: String,
    pub attributes: LightRegistrationData,
}

#[derive(Deserialize, Debug)]
pub struct VerifySodResponse {
    pub data: VerifySodResponseData,
}
