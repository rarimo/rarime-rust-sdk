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
                state_keeper_contract_address: "0x9EDADB216C1971cf0343b8C687cF76E7102584DB"
                    .to_string(),
            },
            api_configuration: RarimeAPIConfiguration {
                json_rpc_evm_url: "https://rpc.evm.mainnet.rarimo.com".to_string(),
                rarime_api_url: "https://api.orgs.app.stage.rarime.com".to_string(),
            },
            user_configuration: RarimeUserConfiguration {
                user_private_key: Some(
                    <[u8; 32]>::try_from(
                        hex::decode(json_value.get("pk").unwrap().as_str().unwrap()).unwrap(),
                    )
                    .unwrap(),
                ),
            },
        };

        let mut rarime = Rarime::new(rarime_config);

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

        // Вызов verify_sod обернут в spawn_blocking
        let result = tokio::task::spawn_blocking(move || {
            // здесь будет выполняться blocking код, включая noir_rs
            futures::executor::block_on(rarime.verify_sod(&passport))
        })
        .await
        .unwrap()
        .unwrap();

        println!("{:#?}", result);
    }

    #[tokio::test]
    async fn test_dg15_ecdsa() {
        let json_string = fs::read_to_string("./tests/assets/passports/dg15_Ecdsa.json").unwrap();
        let json_value: Value = serde_json::from_str(&json_string).unwrap();

        let rarime_config = RarimeConfiguration {
            contracts_configuration: RarimeContractsConfiguration {
                state_keeper_contract_address: "0x9EDADB216C1971cf0343b8C687cF76E7102584DB"
                    .to_string(),
            },
            api_configuration: RarimeAPIConfiguration {
                json_rpc_evm_url: "https://rpc.evm.mainnet.rarimo.com".to_string(),
                rarime_api_url: "https://api.orgs.app.stage.rarime.com".to_string(),
            },
            user_configuration: RarimeUserConfiguration {
                user_private_key: Some(
                    <[u8; 32]>::try_from(
                        hex::decode(json_value.get("pk").unwrap().as_str().unwrap()).unwrap(),
                    )
                    .unwrap(),
                ),
            },
        };

        let mut rarime = Rarime::new(rarime_config);

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

        let result = tokio::task::spawn_blocking(move || {
            futures::executor::block_on(rarime.verify_sod(&passport))
        })
        .await
        .unwrap()
        .unwrap();

        println!("{:#?}", result);
    }

    #[tokio::test]
    async fn test_no_dg15() {
        let json_string = fs::read_to_string("./tests/assets/passports/no_dg15.json").unwrap();
        let json_value: Value = serde_json::from_str(&json_string).unwrap();

        let rarime_config = RarimeConfiguration {
            contracts_configuration: RarimeContractsConfiguration {
                state_keeper_contract_address: "0x9EDADB216C1971cf0343b8C687cF76E7102584DB"
                    .to_string(),
            },
            api_configuration: RarimeAPIConfiguration {
                json_rpc_evm_url: "https://rpc.evm.mainnet.rarimo.com".to_string(),
                rarime_api_url: "https://api.orgs.app.stage.rarime.com".to_string(),
            },
            user_configuration: RarimeUserConfiguration {
                user_private_key: Some(
                    <[u8; 32]>::try_from(
                        hex::decode(json_value.get("pk").unwrap().as_str().unwrap()).unwrap(),
                    )
                    .unwrap(),
                ),
            },
        };

        let mut rarime = Rarime::new(rarime_config);

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

        let result = tokio::task::spawn_blocking(move || {
            futures::executor::block_on(rarime.verify_sod(&passport))
        })
        .await
        .unwrap()
        .unwrap();

        println!("{:#?}", result);
    }
}
