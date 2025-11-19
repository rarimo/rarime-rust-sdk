use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProofError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("SRS setup error: {0}")]
    Srs(String),
    #[error("Witness error: {0}")]
    Witness(String),
    #[error("Proving system error: {0}")]
    ProvingError(String),
    #[error("JSON structure missing field: {0}")]
    MissingField(String),
}
