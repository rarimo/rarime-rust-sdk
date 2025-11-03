#[cfg(test)]
mod tests {
    use rarime_rust_sdk::{
        Rarime, RarimeAPIConfiguration, RarimeConfiguration, RarimeContractsConfiguration,
        RarimeUserConfiguration,
    };

    #[tokio::test]
    async fn get_polls_data_test_contracts() {
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
                ipfs_url: "https://ipfs.rarimo.com".to_string(),
            },
            user_configuration: RarimeUserConfiguration {
                user_private_key: vec![0; 32],
            },
        };

        let rarime = Rarime::new(rarime_config).unwrap();

        let proposal_id: String = "208".to_string();

        let proposal_data = rarime.get_polls_data_contract(proposal_id).await.unwrap();
        dbg!(&proposal_data);
    }

    #[tokio::test]
    async fn get_polls_data_test_ipfs() {
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
                ipfs_url: "https://ipfs.rarimo.com".to_string(),
            },
            user_configuration: RarimeUserConfiguration {
                user_private_key: vec![0; 32],
            },
        };

        let rarime = Rarime::new(rarime_config).unwrap();

        let proposal_id: String = "208".to_string();

        let proposal_data = rarime.get_polls_data_ipfs(proposal_id).await.unwrap();
        dbg!(&proposal_data);
    }
}
