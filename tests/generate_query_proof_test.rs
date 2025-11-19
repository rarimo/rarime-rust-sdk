#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use rarime_rust_sdk::rarime::{
        Rarime, RarimeAPIConfiguration, RarimeConfiguration, RarimeContractsConfiguration,
        RarimeUserConfiguration,
    };
    use rarime_rust_sdk::{QueryProofParams, RarimePassport};
    use serde_json::Value;
    use std::fs;

    #[tokio::test]
    async fn test_query_proof() {
        let json_string = fs::read_to_string("./tests/assets/passports/id_card3.json").unwrap();
        let json_value: Value = serde_json::from_str(&json_string).unwrap();

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
                    "090ad31e17fa6d91dd575249db8e721262f988eac3bfe9b4d5366415a7995865",
                )
                .unwrap(),
            },
        };

        let rarime = Rarime::new(rarime_config).unwrap();

        let passport = RarimePassport {
            data_group1: STANDARD
                .decode(json_value.get("dg1").unwrap().as_str().unwrap())
                .unwrap(),
            data_group15:
            // None,
            Some(
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
            event_id: "43580365239758335475".to_string(),
            event_data:
                "270038666511201875208172000617689023489105079510191335498520083214634616239"
                    .to_string(),
            selector: "0".to_string(),
            timestamp_lowerbound: "0".to_string(),
            timestamp_upperbound: "0".to_string(),
            identity_count_lowerbound: "0".to_string(),
            identity_count_upperbound: "0".to_string(),
            birth_date_lowerbound: "52983525027888".to_string(),
            birth_date_upperbound: "52983525027888".to_string(),
            expiration_date_lowerbound: "52983525027888".to_string(),
            expiration_date_upperbound: "52983525027888".to_string(),
            citizenship_mask: "0".to_string(),
        };

        let result = tokio::task::spawn_blocking({
            let passport = passport.clone();
            let query_params = query_params.clone();
            let rarime = rarime.clone();
            move || futures::executor::block_on(rarime.generate_query_proof(passport, query_params))
        })
        .await
        .unwrap()
        .unwrap();

        for (i, chunk) in result.chunks(32).take(24).enumerate() {
            dbg!(format!("{}: 0x{}", i + 1, hex::encode(chunk)));
        }
        dbg!(hex::encode(result[768..].to_vec()));

        dbg!(hex::encode(&result));
    }
}
