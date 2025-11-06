use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SendTransactionRequest {
    pub data: SendTransactionData,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendTransactionData {
    #[serde(rename = "type")]
    pub transaction_type: String,
    pub attributes: SendTransactionAttributes,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendTransactionAttributes {
    pub tx_data: String,
    pub destination: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendTransactionResponse {
    pub data: TxData,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TxData {
    pub id: String,
    #[serde(rename = "type")]
    pub transaction_type: String,
}
