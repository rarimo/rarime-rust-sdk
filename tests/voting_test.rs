#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use rarime_rust_sdk::RarimePassport;
    use rarime_rust_sdk::freedomtool::{
        Freedomtool, FreedomtoolAPIConfiguration, FreedomtoolConfiguration,
        FreedomtoolContractsConfiguration,
    };
    use rarime_rust_sdk::rarime::{
        Rarime, RarimeAPIConfiguration, RarimeConfiguration, RarimeContractsConfiguration,
        RarimeUserConfiguration,
    };
    use serde_json::Value;
    use std::fs;

    #[tokio::test]
    async fn send_vote_test() {
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

        let proposal_id: String = "217".to_string();

        let proposal_data_contract = freedomtool
            .get_polls_data_contract(proposal_id.clone())
            .await
            .unwrap();

        let proposal_data = freedomtool
            .get_polls_data_ipfs(proposal_data_contract.config.description)
            .await
            .unwrap();

        let answers = vec![1];

        let proposal_criteria = freedomtool
            .get_proposal_rules(
                proposal_id.clone(),
                proposal_data_contract.config.votingWhitelist[0].to_string(),
            )
            .await
            .unwrap();

        let rarime_config = RarimeConfiguration {
            contracts_configuration: RarimeContractsConfiguration {
                state_keeper_address: "0x9EDADB216C1971cf0343b8C687cF76E7102584DB".to_string(),
                register_contract_address: "0xd63782478CA40b587785700Ce49248775398b045".to_string(),
                poseidon_smt_address: "0xF19a85B10d705Ed3bAF3c0eCe3E73d8077Bf6481".to_string(),
            },
            api_configuration: RarimeAPIConfiguration {
                json_rpc_evm_url: "https://rpc.evm.mainnet.rarimo.com".to_string(),
                rarime_api_url: "https://api.orgs.app.stage.rarime.com".to_string(),
            },
            user_configuration: RarimeUserConfiguration {
                user_private_key: hex::decode(
                    "090ad31e17fa6d91dd575249db8e721262f988eac3bfe9b4d5366415a7995865", //TODO: Change this after light_register_test
                )
                .unwrap(),
            },
        };

        let rarime = Rarime::new(rarime_config).unwrap();

        let json_string = fs::read_to_string("./tests/assets/passports/id_card3.json").unwrap();
        let json_value: Value = serde_json::from_str(&json_string).unwrap();

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

        let result = tokio::task::spawn_blocking({
            move || {
                futures::executor::block_on(async move {
                    freedomtool
                        .send_vote(
                            answers,
                            proposal_criteria,
                            rarime,
                            passport,
                            proposal_data_contract.config.votingWhitelist[0].to_string(),
                            proposal_id,
                        )
                        .await
                })
            }
        })
        .await
        .unwrap()
        .unwrap();

        dbg!(result);
    }
}
