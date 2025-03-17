use std::{fs::File, io::Read};

use rarime_rust_sdk::passport::Passport;

#[test]
fn test_passport_parsing() {
    let mut file = File::open("tests/assets/test_passport.json")
        .expect("failed to open test passport data");

    let mut passport_data = String::new();
    file.read_to_string(&mut passport_data)
        .expect("failed to read test passport data");

    let passport: Passport = serde_json::from_str(&passport_data)
        .expect("failed to parse passport");
}