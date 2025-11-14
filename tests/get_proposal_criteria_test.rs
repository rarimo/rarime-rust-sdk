#[cfg(test)]
mod tests {
    use rarime_rust_sdk::freedomtool::{
        Freedomtool, FreedomtoolAPIConfiguration, FreedomtoolConfiguration,
        FreedomtoolContractsConfiguration,
    };

    #[tokio::test]
    async fn get_vote_criteria_test() {
        let freedomtool_config = FreedomtoolConfiguration {
            contracts_configuration: FreedomtoolContractsConfiguration {
                proposals_state_address: "0x4C61d7454653720DAb9e26Ca25dc7B8a5cf7065b".to_string(),
            },
            api_configuration: FreedomtoolAPIConfiguration {
                voting_rpc_url: "https://rpc.qtestnet.org".to_string(),
                ipfs_url: "https://ipfs.rarimo.com".to_string(),
                relayer_url: "http://127.0.0.1:8000".to_string(),
            },
        };

        let freedomtool = Freedomtool::new(freedomtool_config);

        let proposal_id = "209".to_string();

        let proposal_data_contract = freedomtool
            .get_polls_data_contract(proposal_id.clone())
            .await
            .unwrap();

        dbg!(&proposal_data_contract);

        let voting_address = proposal_data_contract.config.votingWhitelist[0].to_string();
        dbg!(&voting_address);

        let proposal_criteria = freedomtool
            .get_proposal_rules(proposal_id, voting_address)
            .await
            .unwrap();

        dbg!(&proposal_criteria);
    }
}
