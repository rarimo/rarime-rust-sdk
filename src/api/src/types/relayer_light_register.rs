use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterResponseBody {
    pub data: LiteRegisterResponse,
    pub included: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LiteRegisterResponse {
    pub id: String,
    #[serde(rename = "type")]
    pub type_field: String,
    pub attributes: RegisterResponseAttributes,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterResponseAttributes {
    pub tx_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LiteRegisterRequest {
    pub data: LiteRegisterData,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LiteRegisterData {
    pub tx_data: String,
    pub no_send: bool,
    pub destination: String,
}
