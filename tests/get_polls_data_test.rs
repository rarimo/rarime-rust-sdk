#[cfg(test)]
mod tests {
    use rarime_rust_sdk::freedomtool::{
        Freedomtool, FreedomtoolAPIConfiguration, FreedomtoolConfiguration,
        FreedomtoolContractsConfiguration,
    };

    #[tokio::test]
    async fn get_polls_data_test_contracts() {
        let freedomtool_config = FreedomtoolConfiguration {
            contracts_configuration: FreedomtoolContractsConfiguration {
                proposals_state_address: "0x4C61d7454653720DAb9e26Ca25dc7B8a5cf7065b".to_string(),
            },
            api_configuration: FreedomtoolAPIConfiguration {
                voting_rpc_url: "https://rpc.qtestnet.org".to_string(),
                ipfs_url: "https://ipfs.rarimo.com".to_string(),
            },
        };

        let freedomtool = Freedomtool::new(freedomtool_config);

        let proposal_id: String = "208".to_string();

        let proposal_data = freedomtool
            .get_polls_data_contract(proposal_id)
            .await
            .unwrap();
        dbg!(&proposal_data);
    }

    #[tokio::test]
    async fn get_polls_data_test_ipfs() {
        let freedomtool_config = FreedomtoolConfiguration {
            contracts_configuration: FreedomtoolContractsConfiguration {
                proposals_state_address: "0x4C61d7454653720DAb9e26Ca25dc7B8a5cf7065b".to_string(),
            },
            api_configuration: FreedomtoolAPIConfiguration {
                voting_rpc_url: "https://rpc.qtestnet.org".to_string(),
                ipfs_url: "https://ipfs.rarimo.com".to_string(),
            },
        };

        let rarime = Freedomtool::new(freedomtool_config);

        let proposal_id: String = "208".to_string();

        let proposal_id: String = "208".to_string();

        let proposal_data_contract = rarime.get_polls_data_contract(proposal_id).await.unwrap();

        let proposal_data = rarime
            .get_polls_data_ipfs(&proposal_data_contract.config.description)
            .await
            .unwrap();
        dbg!(&proposal_data);
    }
}
