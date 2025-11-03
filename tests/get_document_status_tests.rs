#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use rarime_rust_sdk::{
        Rarime, RarimeAPIConfiguration, RarimeConfiguration, RarimeContractsConfiguration,
        RarimePassport, RarimeUserConfiguration,
    };
    use serde_json::Value;
    use std::fs;

    #[tokio::test]
    async fn test_dg15_rsa() {
        let json_string = fs::read_to_string("./tests/assets/passports/dg15_Rsa.json").unwrap();
        let json_value: Value = serde_json::from_str(&json_string).unwrap();
        let rarime_config = RarimeConfiguration {
            contracts_configuration: RarimeContractsConfiguration {
                state_keeper_address: "0x9EDADB216C1971cf0343b8C687cF76E7102584DB".to_string(),
                register_contract_address: "0xd63782478CA40b587785700Ce49248775398b045".to_string(),
                poseidon_smt_address: "0xF19a85B10d705Ed3bAF3c0eCe3E73d8077Bf6481".to_string(),
                proposals_state_address: "0x4C61d7454653720DAb9e26Ca25dc7B8a5cf7065b".to_string(),
            },
            api_configuration: RarimeAPIConfiguration {
                json_rpc_evm_url: "https://rpc.evm.mainnet.rarimo.com".to_string(),
                rarime_api_url: "https://api.orgs.app.stage.rarime.com".to_string(),
                voting_rpc_url: "https://rpc.qtestnet.org".to_string(),
                ipfs_url: "https://ipfs.rarimo.com/ipfs".to_string(),
            },
            user_configuration: RarimeUserConfiguration {
                user_private_key: hex::decode(json_value.get("pk").unwrap().as_str().unwrap())
                    .unwrap(),
            },
        };

        let rarime = Rarime::new(rarime_config).unwrap();

        let passport = RarimePassport {
            data_group1: STANDARD
                .decode(json_value.get("dg1").unwrap().as_str().unwrap())
                .unwrap(),
            data_group15: Some(
                STANDARD
                    .decode(json_value.get("dg15").unwrap().as_str().unwrap())
                    .unwrap(),
            ),
            aa_signature: None,
            aa_challenge: None,
            sod: STANDARD
                .decode(json_value.get("sod").unwrap().as_str().unwrap())
                .unwrap(),
        };

        let result = rarime.get_document_status(passport).await.unwrap();

        dbg!(result);
    }

    #[tokio::test]
    async fn test_dg15_ecdsa() {
        let json_string = fs::read_to_string("./tests/assets/passports/dg15_Ecdsa.json").unwrap();
        let json_value: Value = serde_json::from_str(&json_string).unwrap();
        let rarime_config = RarimeConfiguration {
            contracts_configuration: RarimeContractsConfiguration {
                state_keeper_address: "0x9EDADB216C1971cf0343b8C687cF76E7102584DB".to_string(),
                register_contract_address: "".to_string(),
                poseidon_smt_address: "".to_string(),
                proposals_state_address: "".to_string(),
            },
            api_configuration: RarimeAPIConfiguration {
                json_rpc_evm_url: "https://rpc.evm.mainnet.rarimo.com".to_string(),
                rarime_api_url: "https://api.orgs.app.stage.rarime.com".to_string(),
                voting_rpc_url: "".to_string(),
                ipfs_url: "".to_string(),
            },
            user_configuration: RarimeUserConfiguration {
                user_private_key: hex::decode(json_value.get("pk").unwrap().as_str().unwrap())
                    .unwrap(),
            },
        };

        let rarime = Rarime::new(rarime_config).unwrap();

        let passport = RarimePassport {
            data_group1: STANDARD
                .decode(json_value.get("dg1").unwrap().as_str().unwrap())
                .unwrap(),
            data_group15: Some(
                STANDARD
                    .decode(json_value.get("dg15").unwrap().as_str().unwrap())
                    .unwrap(),
            ),
            aa_signature: None,
            aa_challenge: None,
            sod: STANDARD
                .decode(json_value.get("sod").unwrap().as_str().unwrap())
                .unwrap(),
        };

        let result = rarime.get_document_status(passport).await.unwrap();

        dbg!(result);
    }

    #[tokio::test]
    async fn test_no_dg15() {
        let json_string = fs::read_to_string("./tests/assets/passports/no_dg15.json").unwrap();
        let json_value: Value = serde_json::from_str(&json_string).unwrap();
        let rarime_config = RarimeConfiguration {
            contracts_configuration: RarimeContractsConfiguration {
                state_keeper_address: "0x9EDADB216C1971cf0343b8C687cF76E7102584DB".to_string(),
                register_contract_address: "".to_string(),
                poseidon_smt_address: "".to_string(),
                proposals_state_address: "".to_string(),
            },
            api_configuration: RarimeAPIConfiguration {
                json_rpc_evm_url: "https://rpc.evm.mainnet.rarimo.com".to_string(),
                rarime_api_url: "https://api.orgs.app.stage.rarime.com".to_string(),
                voting_rpc_url: "".to_string(),
                ipfs_url: "".to_string(),
            },
            user_configuration: RarimeUserConfiguration {
                user_private_key: hex::decode(json_value.get("pk").unwrap().as_str().unwrap())
                    .unwrap(),
            },
        };

        let rarime = Rarime::new(rarime_config).unwrap();

        let passport = RarimePassport {
            data_group1: STANDARD
                .decode(json_value.get("dg1").unwrap().as_str().unwrap())
                .unwrap(),
            data_group15: None,
            aa_signature: None,
            aa_challenge: None,
            sod: STANDARD
                .decode(json_value.get("sod").unwrap().as_str().unwrap())
                .unwrap(),
        };

        let result = rarime.get_document_status(passport).await.unwrap();
        dbg!(result);
    }
}
