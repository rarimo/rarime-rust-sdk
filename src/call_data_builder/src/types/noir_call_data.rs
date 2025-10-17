pub struct NoirCallDataInputs {
    pub full_proof: Vec<u8>,
    pub aa_signature: Vec<u8>,
    pub aa_pubkey_pem: Vec<u8>,
    pub ec_size_in_bits: usize,
    pub certificates_root_raw: Vec<u8>,
    pub is_revoked: bool,
    pub circuit_name: String,
}
