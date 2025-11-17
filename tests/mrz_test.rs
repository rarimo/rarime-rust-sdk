#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    use rarime_rust_sdk::RarimePassport;
    use serde_json::Value;
    use std::fs;

    #[test]
    fn get_mrz_test() {
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

        let mrz_date = passport.get_mrz_data().unwrap();

        dbg!(&mrz_date);
    }
}
