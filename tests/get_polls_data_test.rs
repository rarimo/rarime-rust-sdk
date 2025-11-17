#[cfg(test)]
mod tests {
    use rarime_rust_sdk::freedomtool::{
        Freedomtool, FreedomtoolAPIConfiguration, FreedomtoolConfiguration,
        FreedomtoolContractsConfiguration,
    };

    #[tokio::test]
    async fn get_poll_data_test() {
        let freedomtool_config = FreedomtoolConfiguration {
            contracts_configuration: FreedomtoolContractsConfiguration {
                proposals_state_address: "0x4C61d7454653720DAb9e26Ca25dc7B8a5cf7065b".to_string(),
            },
            api_configuration: FreedomtoolAPIConfiguration {
                voting_rpc_url: "https://rpc.qtestnet.org".to_string(),
                ipfs_url: "https://ipfs.rarimo.com".to_string(),
                relayer_url: "".to_string(),
            },
        };

        let freedomtool = Freedomtool::new(freedomtool_config);

        let proposal_id: String = "218".to_string();

        let poll_data = freedomtool.get_proposal_data(proposal_id).await.unwrap();

        dbg!(&poll_data);
    }
}
