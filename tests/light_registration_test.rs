#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use rarime_rust_sdk::RarimePassport;
    use rarime_rust_sdk::rarime::{
        Rarime, RarimeAPIConfiguration, RarimeConfiguration, RarimeContractsConfiguration,
        RarimeUserConfiguration,
    };
    use rarime_rust_sdk::rarimo_utils::RarimeUtils;
    use serde_json::Value;
    use std::fs;

    #[tokio::test]
    async fn test_light_registration() {
        let json_string = fs::read_to_string("./tests/assets/passports/id_card3.json").unwrap();
        let json_value: Value = serde_json::from_str(&json_string).unwrap();

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
                user_private_key: RarimeUtils.generate_bjj_private_key().unwrap(),
            },
        };

        dbg!(hex::encode(
            &rarime_config.user_configuration.user_private_key
        ));

        let rarime = Rarime::new(rarime_config).unwrap();

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
        let result = tokio::task::spawn_blocking(move || {
            futures::executor::block_on(rarime.light_registration(passport))
        })
        .await
        .unwrap()
        .unwrap();

        dbg!(result);
    }
}
