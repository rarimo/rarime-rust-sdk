use crate::errors::ApiError;
use crate::types::ipfs_voting::IPFSResponseData;
use crate::types::relayer_light_register::{LiteRegisterRequest, LiteRegisterResponse};
use crate::types::relayer_send_transaction::SendTransactionRequest;
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

        let response = self.client.post(url).json(request).send().await?;

        let status = response.status();

        if status.is_success() {
            let result: VerifySodResponse = response.json().await?;
            return Ok(result);
        }

        let error_body = response.text().await?;

        Err(ApiError::HttpError { body: error_body })
    }

    pub async fn relayer_light_register(
        &self,
        request: &LiteRegisterRequest,
    ) -> Result<LiteRegisterResponse, ApiError> {
        let url = self
            .base_url
            .join("/integrations/registration-relayer/v1/register")
            .map_err(ApiError::UrlError)?;

        let response = self.client.post(url).json(request).send().await?;

        let status = response.status();

        if status.is_success() {
            let result: LiteRegisterResponse = response.json().await?;
            return Ok(result);
        }

        let error_body = response.text().await?;

        Err(ApiError::HttpError { body: error_body })
    }

    pub async fn relayer_send_transaction(
        &self,
        request: &SendTransactionRequest,
    ) -> Result<LiteRegisterResponse, ApiError> {
        let url = self
            .base_url
            .join("/integrations/registration-relayer/v1/register")
            .map_err(ApiError::UrlError)?;

        let response = self.client.post(url).json(request).send().await?;

        let status = response.status();

        if status.is_success() {
            let result: LiteRegisterResponse = response.json().await?;
            return Ok(result);
        }

        let error_body = response.text().await?;

        Err(ApiError::HttpError { body: error_body })
    }
}

pub struct IPFSApiProvider {
    client: Client,
    base_url: Url,
}

impl IPFSApiProvider {
    pub fn new(base_url: &str) -> Result<Self, ApiError> {
        Ok(IPFSApiProvider {
            client: Client::new(),
            base_url: Url::parse(base_url)?,
        })
    }
    pub async fn get_proposal_data(&self, ipfs_id: &String) -> Result<IPFSResponseData, ApiError> {
        let url = self
            .base_url
            .join(&format!("/ipfs/{}", ipfs_id))
            .map_err(ApiError::UrlError)?;

        let response = self.client.get(url).send().await?;

        let status = response.status();

        if status.is_success() {
            let result: IPFSResponseData = response.json().await?;
            return Ok(result);
        }

        let error_body = response.text().await?;

        return Err(ApiError::HttpError { body: error_body });
    }
}
