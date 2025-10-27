use crate::utils::bytes_to_string_array;
use noir_rs::barretenberg::prove::prove_ultra_plonk;
use noir_rs::barretenberg::srs::setup_srs;
use noir_rs::witness::from_vec_str_to_witness_map;
use serde_json::Value;
use std::fs;
use thiserror::Error;

mod utils;

#[derive(Debug)]
pub struct QueryProofInput {
    pub event_id: String,
    pub event_data: String,
    pub id_state_root: String,
    pub selector: String,
    pub current_date: String,
    pub timestamp_lowerbound: String,
    pub timestamp_upperbound: String,
    pub identity_count_lowerbound: String,
    pub identity_count_upperbound: String,
    pub birth_date_lowerbound: String,
    pub birth_date_upperbound: String,
    pub expiration_date_lowerbound: String,
    pub expiration_date_upperbound: String,
    pub citizenship_mask: String,
    pub sk_identity: String,
    pub pk_passport_hash: String,
    pub dg1: Vec<u8>,
    pub siblings: Vec<String>,
    pub timestamp: String,
    pub identity_counter: String,
}

#[derive(Debug)]
pub struct LiteRegisterProofInput {
    pub dg1: Vec<u8>,
    pub sk: String,
}

pub struct ProofProvider {}

impl ProofProvider {
    pub fn new() -> Self {
        Self {}
    }

    pub fn generate_lite_proof(
        &self,
        hash_size: usize,
        inputs: LiteRegisterProofInput,
    ) -> Result<Vec<u8>, ProofError> {
        let path = format!(
            "src/proofs/src/assets/lite_register/register_lite_{}.json",
            hash_size.to_string()
        );
        let json_string = fs::read_to_string(path).map_err(|e| ProofError::Io(e))?;
        let json_value: Value =
            serde_json::from_str(&json_string).map_err(|e| ProofError::Json(e))?;
        let bytecode_value = json_value
            .get("bytecode")
            .ok_or(ProofError::MissingField("bytecode value".to_string()))?;

        let bytecode = bytecode_value.as_str().ok_or(ProofError::MissingField(
            "bytecode type conversion".to_string(),
        ))?;

        setup_srs(bytecode, None, false).map_err(|e| ProofError::Srs(e))?;

        let mut witness_inputs: Vec<String> = Vec::new();
        witness_inputs.extend(bytes_to_string_array(&inputs.dg1));
        witness_inputs.push(inputs.sk);

        let witness_input_refs = witness_inputs
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>();
        let initial_witness = from_vec_str_to_witness_map(witness_input_refs.clone())
            .map_err(|e| ProofError::Witness(e))?;

        // HACK: This function actually generates an Ultra Honk proof,
        // despite the misleading 'ultra_plonk' name
        let (proof, _) = prove_ultra_plonk(bytecode, initial_witness, false)
            .map_err(|e| ProofError::ProvingError(e))?;
        return Ok(proof);
    }

    pub fn generate_query_proof(&self, inputs: QueryProofInput) -> Result<Vec<u8>, ProofError> {
        let path = "src/proofs/src/assets/query.json".to_string();
        let json_string = fs::read_to_string(path).map_err(|e| ProofError::Io(e))?;
        let json_value: Value =
            serde_json::from_str(&json_string).map_err(|e| ProofError::Json(e))?;
        let bytecode_value = json_value
            .get("bytecode")
            .ok_or(ProofError::MissingField("bytecode value".to_string()))?;

        let bytecode = bytecode_value.as_str().ok_or(ProofError::MissingField(
            "bytecode type conversion".to_string(),
        ))?;

        setup_srs(bytecode, None, false).map_err(|e| ProofError::Srs(e))?;

        let mut witness_inputs: Vec<String> = Vec::new();

        witness_inputs.push(inputs.event_id);
        witness_inputs.push(inputs.event_data);
        witness_inputs.push(inputs.id_state_root);
        witness_inputs.push(inputs.selector);
        witness_inputs.push(inputs.current_date);
        witness_inputs.push(inputs.timestamp_lowerbound);
        witness_inputs.push(inputs.timestamp_upperbound);
        witness_inputs.push(inputs.identity_count_lowerbound);
        witness_inputs.push(inputs.identity_count_upperbound);
        witness_inputs.push(inputs.birth_date_lowerbound);
        witness_inputs.push(inputs.birth_date_upperbound);
        witness_inputs.push(inputs.expiration_date_lowerbound);
        witness_inputs.push(inputs.expiration_date_upperbound);
        witness_inputs.push(inputs.citizenship_mask);
        witness_inputs.push(inputs.sk_identity);
        witness_inputs.push(inputs.pk_passport_hash);
        witness_inputs.extend(bytes_to_string_array(&inputs.dg1));
        witness_inputs.extend(inputs.siblings);
        witness_inputs.push(inputs.timestamp);
        witness_inputs.push(inputs.identity_counter);

        let witness_input_refs = witness_inputs
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>();
        let initial_witness = from_vec_str_to_witness_map(witness_input_refs.clone())
            .map_err(|e| ProofError::Witness(e))?;

        // HACK: This function actually generates an Ultra Honk proof,
        // despite the misleading 'ultra_plonk' name
        let (proof, _) = prove_ultra_plonk(bytecode, initial_witness, false)
            .map_err(|e| ProofError::ProvingError(e))?;
        return Ok(proof);
    }
}

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
