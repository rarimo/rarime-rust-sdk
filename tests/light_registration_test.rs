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
    async fn test_light_registration() {
        let json_string = fs::read_to_string("./tests/assets/passports/id_card3.json").unwrap();
        let json_value: Value = serde_json::from_str(&json_string).unwrap();

        let rarime_config = RarimeConfiguration {
            contracts_configuration: RarimeContractsConfiguration {
                state_keeper_contract_address: "0x9EDADB216C1971cf0343b8C687cF76E7102584DB"
                    .to_string(),
                register_contract_address: "0xd63782478CA40b587785700Ce49248775398b045".to_string(),
                poseidon_smt_address: "".to_string(),
            },
            api_configuration: RarimeAPIConfiguration {
                json_rpc_evm_url: "https://rpc.evm.mainnet.rarimo.com".to_string(),
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
            futures::executor::block_on(rarime.light_registration(passport))
        })
        .await
        .unwrap()
        .unwrap();

        dbg!(result);
    }

    //     #[test]
    //     fn test() {
    //         let passport_key_str = "5644108600761920898029116442473121668370222676924692844158653099298430003978";
    //         let identity_key_str = "3780309553286379199414996488181274105128323336202740609595406896565517347464";
    //
    //         let passport_bigint = BigInt::from_str(passport_key_str).unwrap();
    //         let identity_bigint = BigInt::from_str(identity_key_str).unwrap();
    // dbg!(&passport_bigint);
    //         dbg!(&identity_bigint);
    //
    //         let passport_key_vec: Vec<u8> = passport_bigint.to_bytes_be().1;
    //         let identity_key_vec: Vec<u8> = identity_bigint.to_bytes_be().1;
    //
    //
    //
    //         let passport_key_u8_32  = vec_u8_to_u8_32(&passport_key_vec).unwrap();
    //         let identity_key_u8_32  = vec_u8_to_u8_32(&identity_key_vec).unwrap();
    //
    //
    //         let result = get_smt_proof_index(&passport_key_u8_32, &identity_key_u8_32).unwrap();
    //
    //
    //         dbg!(result);
    //     }
}
