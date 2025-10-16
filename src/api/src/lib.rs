use crate::errors::ApiError;
use crate::types::relayer_light_register::{LiteRegisterRequest, LiteRegisterResponse};
use crate::types::verify_sod::{VerifySodRequest, VerifySodResponse};
use reqwest::Client;
use url::Url;

pub mod errors;
pub mod types;

pub struct ApiProvider {
    client: Client,
    base_url: Url,
}

impl ApiProvider {
    pub fn new(base_url: &str) -> Result<Self, ApiError> {
        Ok(ApiProvider {
            client: Client::new(),
            base_url: Url::parse(base_url)?,
        })
    }

    pub async fn verify_sod(
        &self,
        request: &VerifySodRequest,
    ) -> Result<VerifySodResponse, ApiError> {
        let url = self
            .base_url
            .join("/integrations/incognito-light-registrator/v1/registerid")
            .map_err(ApiError::UrlError)?;

        let response = self
            .client
            .post(url)
            .json(request)
            .send()
            .await?
            .error_for_status()?;

        let result: VerifySodResponse = response.json().await?;

        Ok(result)
    }

    pub async fn relayer_light_register(
        &self,
        request: &LiteRegisterRequest,
    ) -> Result<LiteRegisterResponse, ApiError> {
        let url = self
            .base_url
            .join("/integrations/registration-relayer/v1/register")
            .map_err(ApiError::UrlError)?;

        let response = self
            .client
            .post(url)
            .json(request)
            .send()
            .await?
            .error_for_status()?;

        let result: LiteRegisterResponse = response.json().await?;

        Ok(result)
    }
}
