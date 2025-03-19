#[cfg(test)]
mod tests {
    use std::{fs::File, io::Read};

    use rarime_rust_sdk::{passport::Passport, rfc::rfc5280};

    #[test]
    fn test_passport_parsing() {
        let mut file = File::open("tests/assets/test_passport.json")
            .expect("failed to open test passport data");

        let mut passport_data = String::new();
        file.read_to_string(&mut passport_data)
            .expect("failed to read test passport data");

        let passport: Passport =
            serde_json::from_str(&passport_data).expect("failed to parse passport");

        let signed_data = passport.parse_signed_data().expect("failed to parse sod");

        let signed_data_version = signed_data.version;

        println!("signed_data_version: {signed_data_version}");

        for choice_cert in signed_data.certificates.unwrap() {
            let cert = match choice_cert {
                asn1::Choice1::ChoiceA(cert) => cert,
            };

            let pub_key_algorithm_id = cert
                .tbs_certificate
                .subject_public_key_info
                .algorithm
                .algorithm
                .clone();

            println!("pub_key_algorithm_id: {pub_key_algorithm_id}");

            if pub_key_algorithm_id == rfc5280::RSA_PUBLIC_KEY_OID {
                let pub_key = cert
                    .tbs_certificate
                    .subject_public_key_info
                    .get_rsa_public_key()
                    .unwrap();

                println!("pub_key_data: {pub_key:?}");
            } else if pub_key_algorithm_id == rfc5280::ECDSA_PUBLIC_KEY_OID {
                let pub_key = cert
                    .tbs_certificate
                    .subject_public_key_info
                    .subject_public_key
                    .as_bytes();

                let pub_key_hex = hex::encode(pub_key);

                println!("pub_key_data: {pub_key_hex}");
            }
        }
    }
}
