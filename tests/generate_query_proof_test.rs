#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use rarime_rust_sdk::{
        QueryProofParams, Rarime, RarimeAPIConfiguration, RarimeConfiguration,
        RarimeContractsConfiguration, RarimePassport, RarimeUserConfiguration, RarimeUtils,
    };
    use serde_json::Value;
    use std::fs;

    #[tokio::test]
    async fn test_light_registration() {
        let json_string = fs::read_to_string("./tests/assets/passports/id_card3.json").unwrap();
        let json_value: Value = serde_json::from_str(&json_string).unwrap();

        let rarime_config = RarimeConfiguration {
            contracts_configuration: RarimeContractsConfiguration {
                state_keeper_contract_address: "0x9EDADB216C1971cf0343b8C687cF76E7102584DB"
                    .to_string(),
                register_contract_address: "0xd63782478CA40b587785700Ce49248775398b045".to_string(),
                poseidon_smt_address: "0xF19a85B10d705Ed3bAF3c0eCe3E73d8077Bf6481".to_string(),
            },
            api_configuration: RarimeAPIConfiguration {
                json_rpc_evm_url: "https://rpc.evm.mainnet.rarimo.com".to_string(),
                rarime_api_url: "https://api.orgs.app.stage.rarime.com".to_string(),
            },
            user_configuration: RarimeUserConfiguration {
                user_private_key: RarimeUtils.generate_bjj_private_key().unwrap(),
            },
        };

        let rarime = Rarime::new(rarime_config).unwrap();

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

        let query_params = QueryProofParams {
            event_id: "".to_string(),
            event_data: "".to_string(),
            selector: "".to_string(),
            timestamp_lowerbound: "".to_string(),
            timestamp_upperbound: "".to_string(),
            identity_count_lowerbound: "".to_string(),
            identity_count_upperbound: "".to_string(),
            birth_date_lowerbound: "".to_string(),
            birth_date_upperbound: "".to_string(),
            expiration_date_lowerbound: "".to_string(),
            expiration_date_upperbound: "".to_string(),
            citizenship_mask: "".to_string(),
        };

        let result = tokio::task::spawn_blocking(move || {
            futures::executor::block_on(rarime.generate_query_proof(passport, query_params))
        })
        .await
        .unwrap()
        .unwrap();

        dbg!(result);
    }
}
