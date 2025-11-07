use crate::rarime::Rarime;
use crate::utils::{big_int_to_32_bytes, calculate_event_nullifier, vec_u8_to_u8_32};
use crate::{QueryProofParams, RarimeError, RarimePassport, VotingCriteria};
use api::IPFSApiProvider;
use api::types::ipfs_voting::IPFSResponseData;
use api::types::relayer_send_transaction::SendTransactionResponse;
use chrono::Utc;
use contracts::ContractCallConfig;
use contracts::IdCardVoting::executeTD1NoirCall;
use contracts::ProposalsState::ProposalInfo;
use contracts::call_data_builder::{CallDataBuilder, UserData, UserPayloadInputs};
use contracts::contract::poseidon_smt::PoseidonSmtContract;
use contracts::contract::proposals_state::ProposalStateContract;
use contracts::utils::{abi_decode_vote_criteria, calculate_voting_event_data, u256_from_string};
use num_bigint::BigInt;
use num_bigint::BigUint;
use num_traits::ToBytes;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct FreedomtoolConfiguration {
    pub api_configuration: FreedomtoolAPIConfiguration,
    pub contracts_configuration: FreedomtoolContractsConfiguration,
}

#[derive(Debug, Clone)]
pub struct FreedomtoolAPIConfiguration {
    pub voting_rpc_url: String,
    pub ipfs_url: String,
}

#[derive(Debug, Clone)]
pub struct FreedomtoolContractsConfiguration {
    pub proposals_state_address: String,
}

pub struct Freedomtool {
    config: FreedomtoolConfiguration,
}

impl Freedomtool {
    pub fn new(config: FreedomtoolConfiguration) -> Self {
        return Self { config };
    }

    /// This function returns data in JSON string format.
    /// Make sure to parse it before using the result.
    pub async fn get_polls_data_ipfs(
        &self,
        ipfs_index: &String,
    ) -> Result<IPFSResponseData, RarimeError> {
        let ipfs_provider = IPFSApiProvider::new(&self.config.api_configuration.ipfs_url)?;

        let proposal_data = ipfs_provider.get_proposal_data(&ipfs_index).await?;

        return Ok(proposal_data);
    }

    pub async fn get_polls_data_contract(
        &self,
        poll_id: String,
    ) -> Result<ProposalInfo, RarimeError> {
        let contract_call_config = ContractCallConfig {
            contract_address: self
                .config
                .contracts_configuration
                .proposals_state_address
                .clone(),
            rpc_url: self.config.api_configuration.voting_rpc_url.clone(),
        };

        let proposals_state = ProposalStateContract::new(contract_call_config);

        let proposal_data = proposals_state.get_proposal_info(&poll_id).await?;

        Ok(proposal_data)
    }

    pub async fn is_already_voted(
        &self,
        proposal_smt_address: String,
        private_key: Vec<u8>,
        event_id: &[u8; 32],
    ) -> Result<bool, RarimeError> {
        let poseidon_smt_call_config = ContractCallConfig {
            rpc_url: self.config.api_configuration.voting_rpc_url.clone(),
            contract_address: proposal_smt_address,
        };

        let poseidon_smt = PoseidonSmtContract::new(poseidon_smt_call_config);

        let private_key_u8_32 = vec_u8_to_u8_32(&private_key)?;

        let nullifier = calculate_event_nullifier(event_id, &private_key_u8_32)?;
        let smt_proof = poseidon_smt.get_proof_call(&nullifier).await?;

        return Ok(smt_proof.existence);
    }

    pub fn abi_decode_proposal_criteria(
        &self,
        voting_whitelist_data: String,
    ) -> Result<VotingCriteria, RarimeError> {
        let voting_data_without_prefix =
            if let Some(stripped) = voting_whitelist_data.strip_prefix("0x") {
                stripped
            } else {
                &voting_whitelist_data
            };
        let data = hex::decode(voting_data_without_prefix)?;

        let decoded_poll_criteria = abi_decode_vote_criteria(&data)?;

        let selector: String = decoded_poll_criteria.0;
        let citizenship_whitelist: Vec<String> = decoded_poll_criteria.1;
        let timestamp_upperbound: String = decoded_poll_criteria.2;
        let identity_count_upperbound: String = decoded_poll_criteria.3;
        let sex: String = decoded_poll_criteria.4;

        let birth_date_lowerbound_big_int = BigUint::from_str(&decoded_poll_criteria.5)?;
        let birth_date_upperbound_big_int = BigUint::from_str(&decoded_poll_criteria.6)?;
        let expiration_date_lowerbound_big_int = BigUint::from_str(&decoded_poll_criteria.7)?;

        let birth_date_lowerbound = format!(
            "0x{}",
            hex::encode(birth_date_lowerbound_big_int.to_be_bytes())
        );
        let birth_date_upperbound = format!(
            "0x{}",
            hex::encode(birth_date_upperbound_big_int.to_be_bytes())
        );
        let expiration_date_lowerbound = format!(
            "0x{}",
            hex::encode(expiration_date_lowerbound_big_int.to_be_bytes())
        );

        let result = VotingCriteria {
            selector,
            citizenship_whitelist,
            timestamp_upperbound,
            identity_count_upperbound,
            sex,
            birth_date_lowerbound,
            birth_date_upperbound,
            expiration_date_lowerbound,
        };

        return Ok(result);
    }

    pub async fn send_vote(
        &self,
        answer: Vec<u8>,
        voting_criteria: VotingCriteria,
        rarime: Rarime,
        passport: RarimePassport,
        contract_voting_address: String,
        proposal_id: String,
    ) -> Result<SendTransactionResponse, RarimeError> {
        let proposal_state_config = ContractCallConfig {
            contract_address: self
                .config
                .contracts_configuration
                .proposals_state_address
                .clone(),
            rpc_url: self.config.api_configuration.voting_rpc_url.clone(),
        };

        let proposal_state = ProposalStateContract::new(proposal_state_config);

        let event_id = proposal_state.get_event_id(&proposal_id).await?;

        let query_proof_params = QueryProofParams {
            event_id: event_id.to_string(),
            event_data: hex::encode(calculate_voting_event_data(&answer)?),
            selector: voting_criteria.selector,
            timestamp_lowerbound: "0".to_string(),
            timestamp_upperbound: voting_criteria.timestamp_upperbound,
            identity_count_lowerbound: "0".to_string(),
            identity_count_upperbound: voting_criteria.identity_count_upperbound,
            birth_date_lowerbound: voting_criteria.birth_date_lowerbound,
            birth_date_upperbound: voting_criteria.birth_date_upperbound,
            expiration_date_lowerbound: voting_criteria.expiration_date_lowerbound,
            expiration_date_upperbound: "303030303030".to_string(),
            citizenship_mask: "0".to_string(),
        };

        let query_proof = rarime
            .generate_query_proof(passport.clone(), query_proof_params)
            .await?;

        let call_data_builder = CallDataBuilder {};

        let passport_info = rarime.get_passport_info(&passport).await?;
        let passport_mrz = passport.get_mrz_string()?;
        let citizenship = passport.get_citizenship(passport_mrz)?;

        let user_payload_inputs = UserPayloadInputs {
            proposal_id: proposal_id.clone(),
            vote: answer.iter().map(|b| b.to_string()).collect(),
            user_data: UserData {
                nullifier:
                // "".to_string(),
                format!(
                    "0x{}",
                    hex::encode(calculate_event_nullifier(&big_int_to_32_bytes(&BigInt::from_str(&proposal_id)?), &rarime.get_private_key()?)?)
                ),
                citizenship: citizenship,
                identity_creation_timestamp: passport_info.identityInfo_.issueTimestamp.to_string(),
            },
        };

        let user_payload = call_data_builder.encode_user_payload(user_payload_inputs)?;

        let smt_proof = rarime.get_smt_proof(&passport).await?;

        let now_time = Utc::now().format("%y%m%d").to_string();
        let current_date_big_int = BigUint::from_bytes_be(now_time.as_bytes());

        let inputs = executeTD1NoirCall {
            registrationRoot_: smt_proof.root,
            currentDate_: u256_from_string(current_date_big_int.to_string())?,
            userPayload_: user_payload.into(),
            zkPoints_: query_proof.into(),
        };

        let call_data = call_data_builder.build_noir_vote_call_data(inputs)?;

        let result = rarime
            .send_transaction(&call_data, contract_voting_address)
            .await?;

        return Ok(result);
    }
}
