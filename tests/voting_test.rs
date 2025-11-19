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
                relayer_url: "https://api.stage.freedomtool.org".to_string(),
            },
        };

        let freedomtool = Freedomtool::new(freedomtool_config);

        let proposal_id: String = "220".to_string();

        let poll_data = freedomtool.get_proposal_data(proposal_id).await.unwrap();

        let rarime_config = RarimeConfiguration {
            contracts_configuration: RarimeContractsConfiguration {
                state_keeper_address: "0x12883d5F530AF7EC2adD7cEC29Cf84215efCf4D8".to_string(),
                register_contract_address: "0x1b6ae4b80F0f26DC53731D1d7aA31fc3996B513B".to_string(),
                poseidon_smt_address: "0xb8bAac4C443097d697F87CC35C5d6B06dDe64D60".to_string(),
            },
            api_configuration: RarimeAPIConfiguration {
                json_rpc_evm_url: "https://rpc.qtestnet.org/".to_string(),
                rarime_api_url: "https://api.orgs.app.stage.rarime.com".to_string(),
            },
            user_configuration: RarimeUserConfiguration {
                user_private_key: hex::decode(
                    "0e5f8f6e7a5cddf009d1f9fbdc9429866927b5f6d8c974a673c912beeb00d825",
                )
                .unwrap(),
            },
        };

        let rarime = Rarime::new(rarime_config).unwrap();

        let json_string = fs::read_to_string("./tests/assets/passports/id_card.json").unwrap();
        let json_value: Value = serde_json::from_str(&json_string).unwrap();

        let passport = RarimePassport {
            data_group1: STANDARD
                .decode(json_value.get("dg1").unwrap().as_str().unwrap())
                .unwrap(),
            data_group15: None,
            // Some(
            //     STANDARD
            //         .decode(json_value.get("dg15").unwrap().as_str().unwrap())
            //         .unwrap(),
            // ),
            aa_signature: None,
            aa_challenge: None,
            sod: STANDARD
                .decode(json_value.get("sod").unwrap().as_str().unwrap())
                .unwrap(),
        };

        let answers = vec![2];

        let result = tokio::task::spawn_blocking({
            move || {
                futures::executor::block_on(async move {
                    freedomtool
                        .send_vote(answers, poll_data, &rarime, passport)
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
