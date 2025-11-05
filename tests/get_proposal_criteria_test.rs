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
            },
        };

        let freedomtool = Freedomtool::new(freedomtool_config);

        let hex_string = "0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000001a0100000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000068f81e80000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000303030303030000000000000000000000000000000000000000000000000000030303030303000000000000000000000000000000000000000000000000000003235313032320000000000000000000000000000000000000000000000000000000000000000".to_string();

        let proposal_criteria = freedomtool
            .abi_decode_proposal_criteria(hex_string)
            .unwrap();
        dbg!(&proposal_criteria);
    }
}
