#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use rarime_rust_sdk::{
        Rarime, RarimeAPIConfiguration, RarimeConfiguration, RarimeContractsConfiguration,
        RarimePassport, RarimeUserConfiguration, RarimeUtils,
    };
    use serde_json::Value;
    use std::fs;

    #[tokio::test]
    async fn test_verify_sod() {
        let json_string = fs::read_to_string("./tests/assets/passports/id_card3.json").unwrap();
        let json_value: Value = serde_json::from_str(&json_string).unwrap();

        let rarime_config = RarimeConfiguration {
            contracts_configuration: RarimeContractsConfiguration {
                state_keeper_contract_address: "0x9EDADB216C1971cf0343b8C687cF76E7102584DB"
                    .to_string(),
                register_contract_address: "0xd63782478CA40b587785700Ce49248775398b045".to_string(),
            },
            api_configuration: RarimeAPIConfiguration {
                json_rpc_evm_url: "https://rpc.evm.mainnet.rarimo.com".to_string(),
                rarime_api_url: "https://api.orgs.app.stage.rarime.com".to_string(),
            },
            user_configuration: RarimeUserConfiguration {
                user_private_key: RarimeUtils::generate_bjj_private_key().unwrap(),
            },
        };

        let mut rarime = Rarime::new(rarime_config.clone());

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

        let proof = tokio::task::spawn_blocking({
            let passport = passport.clone();
            let user_key = rarime_config.user_configuration.user_private_key.clone();
            move || passport.prove_dg1(&user_key).unwrap()
        })
        .await
        .unwrap();

        let result = rarime.verify_sod(&passport, &proof).await.unwrap();

        dbg!(result);
    }
}
