#[cfg(test)]
mod tests {
    use std::{fs::File, io::Read};

    use rarime_rust_sdk::{
        masters_certificate_pool::MastersCertificatePool, passport::Passport, rfc::rfc5280,
    };

    #[test]
    fn test_certificate_pool() {
        let mut passport_file = File::open("tests/assets/test_passport.json")
            .expect("failed to open test passport data");

        let mut passport_data = String::new();
        passport_file
            .read_to_string(&mut passport_data)
            .expect("failed to read test passport data");

        let passport: Passport =
            serde_json::from_str(&passport_data).expect("failed to parse passport");

        let signed_data = passport.parse_signed_data().expect("failed to parse sod");

        let asn1::Choice1::ChoiceA(slave) = signed_data
            .certificates
            .expect("at least one certificate should be present")
            .last()
            .unwrap();

        let mut masters_pems_file =
            File::open("tests/assets/masters.pem").expect("failed to open certificate masters");

        let mut masters_pems_data = String::new();
        masters_pems_file
            .read_to_string(&mut masters_pems_data)
            .expect("failed to read certificate masters data");

        let masters_pems = pem::parse_many(&masters_pems_data).expect("failed to parse raw pems");

        let mut master_certificates: Vec<rfc5280::Certificate> = vec![];
        for master_pem in &masters_pems {
            let certificate: rfc5280::Certificate =
                asn1::parse_single(master_pem.contents()).expect("failed to parse master_pem");

            master_certificates.push(certificate);
        }

        let mut masters_certificate_pool = MastersCertificatePool::new();
        masters_certificate_pool.add_masters(master_certificates);

        let master = masters_certificate_pool
            .find_master(&slave)
            .expect("failed to find master");

        match master {
            Some(_) => {
                println!("master found");
            }
            None => {
                println!("master not found");
            }
        }
    }
}
