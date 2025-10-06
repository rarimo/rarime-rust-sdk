use crate::utils::bytes_to_string_array;
use noir_rs::barretenberg::prove::prove_ultra_plonk;
use noir_rs::barretenberg::srs::setup_srs;
use noir_rs::witness::from_vec_str_to_witness_map;
use serde_json::Value;
use std::fs;
use thiserror::Error;

mod utils;

pub struct ProofInput {
    pub dg1_commitment: Vec<u8>,
    pub dg1_hash: Vec<u8>,
    pub profile_key: Vec<u8>,
}

pub struct ProofProvider {
    inputs: ProofInput,
    hash_size: usize,
}

impl ProofProvider {
    pub fn new(inputs: ProofInput, hash_size: usize) -> Self {
        Self { inputs, hash_size }
    }

    pub fn generate_lite_proof(&self) -> Result<Vec<u8>, ProofError> {
        let path = format!(
            "src/assets/register_lite_{}.json",
            self.hash_size.to_string()
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

        witness_inputs.extend(bytes_to_string_array(&self.inputs.dg1_commitment)); // dg1_commitment
        witness_inputs.extend(bytes_to_string_array(&self.inputs.dg1_hash)); // dg1_hash
        witness_inputs.extend(bytes_to_string_array(&self.inputs.profile_key)); // sk_hash

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
