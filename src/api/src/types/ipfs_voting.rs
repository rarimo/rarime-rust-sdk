use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct OptionVariant {
    pub title: String,
    pub description: Option<String>,
    pub variants: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IPFSResponseData {
    pub title: String,
    pub description: Option<String>,
    #[serde(rename = "acceptedOptions")]
    pub accepted_options: Vec<OptionVariant>,
    #[serde(rename = "imageCid")]
    pub image_cid: Option<String>,
    #[serde(rename = "rankingBased")]
    pub ranking_based: Option<bool>, // for now this not send in production
}
