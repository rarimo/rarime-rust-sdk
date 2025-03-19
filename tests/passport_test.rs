#[cfg(test)]
mod tests {
    use std::{fs::File, io::Read};

    use rarime_rust_sdk::passport::Passport;

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
    }
}
