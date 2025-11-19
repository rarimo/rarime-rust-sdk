use thiserror::Error;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("HTTP request failed: {0}")]
    RequestError(#[from] reqwest::Error),

    #[error("Failed to parse URL: {0}")]
    UrlError(#[from] url::ParseError),

    #[error("Error response: {body}")]
    HttpError { body: String },
}
