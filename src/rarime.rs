use crate::utils::{get_smt_proof_index, poseidon_hash_32_bytes, vec_u8_to_u8_32};
use crate::{DocumentStatus, QueryProofParams, RarimeError, RarimePassport, rarime_utils};
use api::ApiProvider;
use api::types::relayer_light_register::{LiteRegisterData, LiteRegisterRequest};
use api::types::verify_sod::{Attributes, Data, DocumentSod, VerifySodRequest, VerifySodResponse};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use contracts::ContractCallConfig;
use contracts::call_data_builder::CallDataBuilder;
use contracts::contract::poseidon_smt::PoseidonSmtContract;
use contracts::contract::state_keeper::StateKeeperContract;
use contracts::utils::convert_to_u256;
use std::str::FromStr;

use crate::poll::VotingCriteria;
use crate::rarimo_utils::RarimeUtils;
use contracts::RegistrationSimple::{Passport, registerSimpleViaNoirCall};
use contracts::SparseMerkleTree::Proof;
use contracts::StateKeeper::getPassportInfoReturn;
use num_bigint::{BigInt, Sign};
use simple_asn1::to_der;

#[derive(Debug, Clone)]
pub struct RarimeUserConfiguration {
    pub user_private_key: Vec<u8>,
}
#[derive(Debug, Clone)]
pub struct RarimeAPIConfiguration {
    pub json_rpc_evm_url: String,
    pub rarime_api_url: String,
}

#[derive(Debug, Clone)]
pub struct RarimeContractsConfiguration {
    pub state_keeper_address: String,
    pub register_contract_address: String,
    pub poseidon_smt_address: String,
}

#[derive(Debug, Clone)]
pub struct RarimeConfiguration {
    pub contracts_configuration: RarimeContractsConfiguration,
    pub api_configuration: RarimeAPIConfiguration,
    pub user_configuration: RarimeUserConfiguration,
}

#[derive(Debug, Clone)]
pub struct Rarime {
    config: RarimeConfiguration,
}

impl Rarime {
    pub fn new(config: RarimeConfiguration) -> Result<Self, RarimeError> {
        if config.user_configuration.user_private_key.len() != 32 {
            return Err(RarimeError::SetupSDKError(
                "User private key length must be 32".to_string(),
            ));
        }
        return Ok(Self { config });
    }

    pub async fn get_document_status(
        &self,
        passport: RarimePassport,
    ) -> Result<DocumentStatus, RarimeError> {
        let profile_key = rarime_utils::get_profile_key(&vec_u8_to_u8_32(
            &self.config.user_configuration.user_private_key,
        )?)?;

        let passport_info = self.get_passport_info(&passport).await?;

        let result = passport
            .get_document_status(&profile_key, passport_info)
            .await?;

        Ok(result)
    }

    pub async fn verify_sod(
        &self,
        passport: &RarimePassport,
        proof: &[u8],
    ) -> Result<VerifySodResponse, RarimeError> {
        let api_provider = ApiProvider::new(&self.config.api_configuration.rarime_api_url)?;
        let verify_sod_request = VerifySodRequest {
            data: Data {
                id: "".to_string(),
                type_field: "register".to_string(),
                attributes: Attributes {
                    document_sod: DocumentSod {
                        hash_algorithm: passport.get_dg_hash_algorithm()?.to_string(),
                        signature_algorithm: passport.get_signature_algorithm()?.to_string(),
                        signed_attributes: format!(
                            "0x{}",
                            hex::encode(to_der(&passport.extract_signed_attributes()?)?)
                                .to_uppercase()
                        ),
                        encapsulated_content: format!(
                            "0x{}",
                            &hex::encode(to_der(&passport.extract_encapsulated_content()?)?)
                                .to_uppercase()[8..]
                        ),
                        signature: format!(
                            "0x{}",
                            hex::encode(&passport.extract_signature()?).to_uppercase()
                        ),
                        pem_file: passport.get_certificate_pem()?,
                        dg15: match &passport.data_group15 {
                            Some(value) => format!("0x{}", hex::encode(value).to_uppercase()),
                            None => "".to_string(),
                        },
                        aa_signature: match &passport.aa_signature {
                            Some(value) => format!("0x{}", hex::encode(value).to_uppercase()),
                            None => "".to_string(),
                        },
                        sod: format!("0x{}", hex::encode(&passport.sod).to_uppercase()),
                    },
                    zk_proof: STANDARD.encode(&proof),
                },
            },
        };

        let verify_sod_response = api_provider.verify_sod(&verify_sod_request).await?;
        return Ok(verify_sod_response);
    }

    pub(crate) fn build_call_data(
        &self,
        verify_sod_response: &VerifySodResponse,
        passport: &RarimePassport,
        proof: &[u8],
    ) -> Result<Vec<u8>, RarimeError> {
        let public_key: [u8; 32] =
            hex::decode(&verify_sod_response.data.attributes.public_key[2..])?[..32]
                .try_into()
                .map_err(|_| {
                    RarimeError::VectorSizeValidationError(
                        "Vector must be 32 bytes in length".to_string(),
                    )
                })?;

        let call_data_builder = CallDataBuilder::new();
        let inputs = registerSimpleViaNoirCall {
            identityKey_: convert_to_u256(&vec_u8_to_u8_32(
                &RarimeUtils
                    .get_profile_key(self.config.user_configuration.user_private_key.clone())?,
            )?)?,
            passport_: Passport {
                dgCommit: convert_to_u256(&proof[..32].try_into().map_err(|_| {
                    RarimeError::VectorSizeValidationError("Proof length less than 32".to_string())
                })?)?,
                dg1Hash: convert_to_u256(&proof[32..64].try_into().map_err(|_| {
                    RarimeError::VectorSizeValidationError("Proof length less than 64".to_string())
                })?)?
                .into(),
                publicKey: public_key.into(),
                passportHash: passport.get_passport_hash()?.into(),
                verifier: hex::decode(
                    verify_sod_response
                        .data
                        .attributes
                        .verifier
                        .chars()
                        .skip(2)
                        .collect::<String>(),
                )?
                .as_slice()
                .try_into()
                .map_err(|_| {
                    RarimeError::VectorSizeValidationError(
                        "Verifier address is not 20 length".to_string(),
                    )
                })?,
            },
            signature_: hex::decode(&verify_sod_response.data.attributes.signature[2..])?.into(),
            // Remove public signals from the proof
            zkPoints_: proof[96..].to_vec().into(),
        };

        let call_data = call_data_builder.build_noir_lite_register_call_data(inputs)?;
        return Ok(call_data);
    }

    pub async fn light_registration(
        &self,
        passport: RarimePassport,
    ) -> Result<String, RarimeError> {
        let private_key_validate =
            vec_u8_to_u8_32(&self.config.user_configuration.user_private_key)?;

        let proof = passport.prove_dg1(&private_key_validate)?;
        let verify_sod_response = self.verify_sod(&passport, &proof).await?;

        let api_provider = ApiProvider::new(&self.config.api_configuration.rarime_api_url)?;

        let call_data = self.build_call_data(&verify_sod_response, &passport, &proof)?;

        let lite_register_request = LiteRegisterRequest {
            data: LiteRegisterData {
                tx_data: format!("0x{}", hex::encode(&call_data)),
                no_send: false,
                destination: self
                    .config
                    .contracts_configuration
                    .register_contract_address
                    .clone(),
            },
        };
        let lite_register_response = api_provider
            .relayer_light_register(&lite_register_request)
            .await?;

        let tx_hash = lite_register_response.data.attributes.tx_hash;

        return Ok(tx_hash);
    }

    pub async fn generate_query_proof(
        &self,
        passport: RarimePassport,
        query_params: QueryProofParams,
    ) -> Result<Vec<u8>, RarimeError> {
        let passport_info = self.get_passport_info(&passport).await?;

        let pk_u8_32: [u8; 32] = vec_u8_to_u8_32(&self.config.user_configuration.user_private_key)?;

        let smt_proof = self.get_smt_proof(&passport).await?;

        let proof = passport
            .generate_document_query_proof(query_params, &pk_u8_32, smt_proof, passport_info)
            .await?;

        return Ok(proof);
    }

    pub async fn get_passport_info(
        &self,
        passport: &RarimePassport,
    ) -> Result<getPassportInfoReturn, RarimeError> {
        let state_keeper_config = ContractCallConfig {
            rpc_url: self.config.api_configuration.json_rpc_evm_url.clone(),
            contract_address: self
                .config
                .contracts_configuration
                .state_keeper_address
                .clone(),
        };

        let passport_key = passport.get_passport_key()?;

        let state_keeper = StateKeeperContract::new(state_keeper_config);
        let passport_info = state_keeper.get_passport_info(&passport_key).await?;

        return Ok(passport_info);
    }

    pub async fn get_smt_proof(&self, passport: &RarimePassport) -> Result<Proof, RarimeError> {
        let state_keeper_config = ContractCallConfig {
            rpc_url: self.config.api_configuration.json_rpc_evm_url.clone(),
            contract_address: self
                .config
                .contracts_configuration
                .state_keeper_address
                .clone(),
        };

        let poseidon_smt_config = ContractCallConfig {
            rpc_url: self.config.api_configuration.json_rpc_evm_url.clone(),
            contract_address: self
                .config
                .contracts_configuration
                .poseidon_smt_address
                .clone(),
        };

        let pk_key: [u8; 32] = vec_u8_to_u8_32(&self.config.user_configuration.user_private_key)?;

        let passport_key = passport.get_passport_key()?;

        let state_keeper = StateKeeperContract::new(state_keeper_config);
        let passport_info = state_keeper.get_passport_info(&passport_key).await?;
        let utils = RarimeUtils::new();

        let profile_key = vec_u8_to_u8_32(&utils.get_profile_key(pk_key.to_vec())?)?;

        if profile_key != passport_info.passportInfo_.activeIdentity {
            return Err(RarimeError::VectorSizeValidationError(format!(
                "profile key mismatch. profile_key = {},   passport_info.passportInfo_.activeIdentity= {}",
                hex::encode(profile_key),
                hex::encode(passport_info.passportInfo_.activeIdentity)
            )));
        }

        let smt_proof_index = get_smt_proof_index(&passport_key, &profile_key)?;

        let poseidon_smt = PoseidonSmtContract::new(poseidon_smt_config);
        let smt_proof = poseidon_smt.get_proof_call(&smt_proof_index).await?;

        return Ok(smt_proof);
    }

    pub fn calculate_event_nullifier(&self, event_id: String) -> Result<[u8; 32], RarimeError> {
        let private_key_big_int =
            BigInt::from_bytes_be(Sign::Plus, &self.config.user_configuration.user_private_key);

        let secret_key_hash = poseidon_hash_32_bytes(&vec![private_key_big_int.clone()])?;
        let secret_key_hash_big_int = BigInt::from_bytes_be(Sign::Plus, secret_key_hash.as_slice());

        let event_id_big_int = BigInt::from_str(&event_id)?;

        let event_nullifier = poseidon_hash_32_bytes(&vec![
            private_key_big_int,
            secret_key_hash_big_int,
            event_id_big_int,
        ])?;

        return Ok(event_nullifier);
    }

    pub async fn validate_identity(
        &self,
        voting_criteria: &VotingCriteria,
        passport: RarimePassport,
    ) -> Result<(), RarimeError> {
        let passport_info = self.get_passport_info(&passport).await?;

        if u64::from_str(&voting_criteria.timestamp_upperbound)?
            < passport_info.identityInfo_.issueTimestamp
        {
            return Err(RarimeError::ValidationError(
                "Timestamp creation identity is bigger then upperbound".to_string(),
            ));
        }

        if u64::from_str(&voting_criteria.identity_count_upperbound)?
            < passport_info.passportInfo_.identityReissueCounter
        {
            return Err(RarimeError::ValidationError(
                "Identity counter is bigger then upperbound".to_string(),
            ));
        }

        return Ok(());
    }
}
