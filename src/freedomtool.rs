use crate::rarime::Rarime;
use crate::utils::{big_int_to_32_bytes, calculate_event_nullifier, vec_u8_to_u8_32};
use crate::{QueryProofParams, RarimeError, RarimePassport, VotingCriteria};
use api::types::ipfs_voting::IPFSResponseData;
use api::types::relayer_send_transaction::{
    SendTransactionAttributes, SendTransactionData, SendTransactionRequest, SendTransactionResponse,
};
use api::{ApiProvider, IPFSApiProvider};
use chrono::Utc;
use contracts::ContractCallConfig;
use contracts::IdCardVoting::executeTD1NoirCall;
use contracts::ProposalsState::ProposalInfo;
use contracts::call_data_builder::{CallDataBuilder, UserData, UserPayloadInputs};
use contracts::contract::id_card_voting::IdCardVotingContract;
use contracts::contract::poseidon_smt::PoseidonSmtContract;
use contracts::contract::proposals_state::ProposalStateContract;
use contracts::utils::{calculate_voting_event_data, u256_from_string};
use num_bigint::BigInt;
use num_bigint::BigUint;
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
    pub relayer_url: String,
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
        private_key: Vec<u8>,
        event_id: &[u8; 32],
        proposal_smt_address: String,
    ) -> Result<bool, RarimeError> {
        let proposal_smt_call_config = ContractCallConfig {
            rpc_url: self.config.api_configuration.voting_rpc_url.clone(),
            contract_address: proposal_smt_address,
        };

        let poseidon_smt = PoseidonSmtContract::new(proposal_smt_call_config);

        let private_key_u8_32 = vec_u8_to_u8_32(&private_key)?;

        let nullifier = calculate_event_nullifier(event_id, &private_key_u8_32)?;
        let smt_proof = poseidon_smt.get_proof_call(&nullifier).await?;

        return Ok(smt_proof.existence);
    }

    pub async fn get_proposal_rules(
        &self,
        proposal_id: String,
        id_card_voting_address: String,
    ) -> Result<VotingCriteria, RarimeError> {
        let id_card_voting_config = ContractCallConfig {
            rpc_url: self.config.api_configuration.voting_rpc_url.clone(),
            contract_address: id_card_voting_address,
        };
        dbg!(&id_card_voting_config);

        let id_card_voting = IdCardVotingContract::new(id_card_voting_config);
        dbg!(&id_card_voting);

        let proposal_rules = id_card_voting.get_proposal_rules(proposal_id).await?;
        dbg!(&proposal_rules);

        let result = VotingCriteria {
            selector: proposal_rules.selector.to_string(),
            citizenship_whitelist: proposal_rules
                .citizenshipWhitelist
                .iter()
                .map(|x| x.to_string())
                .collect(),
            timestamp_upperbound: proposal_rules
                .identityCreationTimestampUpperBound
                .to_string(),
            identity_count_upperbound: proposal_rules.identityCounterUpperBound.to_string(),
            sex: proposal_rules.sex.to_string(),
            birth_date_lowerbound: proposal_rules.birthDateLowerbound.to_string(),
            birth_date_upperbound: proposal_rules.birthDateUpperbound.to_string(),
            expiration_date_lowerbound: proposal_rules.expirationDateLowerBound.to_string(),
        };

        return Ok(result);
    }

    pub async fn send_vote(
        &self,
        answers: Vec<u8>,
        voting_criteria: VotingCriteria,
        rarime: Rarime,
        passport: RarimePassport,
        contract_voting_address: String,
        proposal_id: String,
    ) -> Result<SendTransactionResponse, RarimeError> {
        const ROOT_VALIDITY: u32 = 3600u32;

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
        dbg!(&event_id);

        let passport_info = rarime.get_passport_info(&passport).await?;

        let timestamp_upperbound = if passport_info.identityInfo_.issueTimestamp > 0 {
            BigUint::from(passport_info.identityInfo_.issueTimestamp)
        } else {
            BigUint::from_str(&voting_criteria.timestamp_upperbound)? - BigUint::from(ROOT_VALIDITY)
        };

        let query_proof_params = QueryProofParams {
            event_id: event_id.to_string(),
            event_data: BigUint::from_bytes_be(&calculate_voting_event_data(&answers)?.to_vec())
                .to_string(),
            selector: voting_criteria.selector,
            timestamp_lowerbound: "0".to_string(),
            timestamp_upperbound: timestamp_upperbound.to_string(),
            identity_count_lowerbound: "0".to_string(),
            identity_count_upperbound: voting_criteria.identity_count_upperbound,
            birth_date_lowerbound: voting_criteria.birth_date_lowerbound,
            birth_date_upperbound: voting_criteria.birth_date_upperbound,
            expiration_date_lowerbound: voting_criteria.expiration_date_lowerbound,
            expiration_date_upperbound: "52983525027888".to_string(),
            citizenship_mask: "0".to_string(),
        };
        dbg!(&query_proof_params);
        let query_proof = rarime
            .generate_query_proof(passport.clone(), query_proof_params)
            .await?;

        for (i, chunk) in query_proof.chunks(32).take(24).enumerate() {
            dbg!(format!("0x{}", hex::encode(chunk)));
        }
        dbg!(hex::encode(query_proof[768..].to_vec()));

        let call_data_builder = CallDataBuilder {};

        let passport_info = rarime.get_passport_info(&passport).await?;
        dbg!(&passport_info);
        let event_nullifier = calculate_event_nullifier(
            &big_int_to_32_bytes(&BigInt::from_str(&event_id.to_string())?),
            &rarime.get_private_key()?,
        )?;

        let user_payload_inputs = UserPayloadInputs {
            proposal_id: proposal_id.clone(),
            vote: answers.iter().map(|b| b.to_string()).collect(),
            user_data: UserData {
                nullifier: BigUint::from_bytes_be(&event_nullifier).to_string(),
                citizenship: BigUint::from_bytes_be(&query_proof[160..192].to_vec()).to_string(),
                identity_creation_timestamp: passport_info.identityInfo_.issueTimestamp.to_string(),
            },
        };
        dbg!(&user_payload_inputs);
        let user_payload = call_data_builder.encode_user_payload(user_payload_inputs)?;
        dbg!(hex::encode(&user_payload).len());
        let smt_proof = rarime.get_smt_proof(&passport).await?;

        let now_time = Utc::now().format("%y%m%d").to_string();
        let current_date_big_int = BigUint::from_bytes_be(now_time.as_bytes());

        let inputs = executeTD1NoirCall {
            registrationRoot_: smt_proof.root,
            currentDate_: u256_from_string(current_date_big_int.to_string())?,
            userPayload_: user_payload.into(),
            zkPoints_: query_proof[768..].to_vec().into(), //cut pub signals
        };
        dbg!(&inputs);
        let call_data = call_data_builder.build_noir_vote_call_data(inputs)?;
        dbg!(&call_data.len());

        let result = self
            .send_transaction(&call_data, contract_voting_address)
            .await?;

        return Ok(result);
    }

    pub async fn send_transaction(
        &self,
        call_data: &Vec<u8>,
        destination: String,
    ) -> Result<SendTransactionResponse, RarimeError> {
        let api_provider = ApiProvider::new(&self.config.api_configuration.relayer_url)?;

        let send_transaction_request = SendTransactionRequest {
            data: SendTransactionData {
                data_type: "send_transaction".to_string(),
                attributes: SendTransactionAttributes {
                    tx_data: format!("0x{}", hex::encode(call_data)),
                    destination: destination,
                },
            },
        };
        dbg!(&send_transaction_request);

        let send_transaction = api_provider
            .relayer_send_vote_transaction(&send_transaction_request)
            .await?;

        return Ok(send_transaction);
    }
}
