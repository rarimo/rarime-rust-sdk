use serde::{Deserialize, Serialize};

///Request types

#[derive(Serialize, Debug)]
pub struct DocumentSod {
    pub hash_algorithm: String,
    pub signature_algorithm: String,
    pub signed_attributes: String,
    pub signature: String,
    pub aa_signature: String,
    pub encapsulated_content: String,
    pub pem_file: String,
    pub dg15: String,
    pub sod: String,
}

#[derive(Serialize, Debug)]
pub struct Attributes {
    pub zk_proof: String,
    pub document_sod: DocumentSod,
}

#[derive(Serialize, Debug)]
pub struct Data {
    pub id: String,
    #[serde(rename = "type")]
    pub type_field: String,
    pub attributes: Attributes,
}

#[derive(Serialize, Debug)]
pub struct VerifySodRequest {
    pub data: Data,
}

///Response types

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

///Error response types

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorDetail {
    pub title: String,
    pub detail: Option<String>,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub errors: Vec<ErrorDetail>,
}
