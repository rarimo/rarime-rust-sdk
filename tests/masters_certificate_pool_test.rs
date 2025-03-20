#[cfg(test)]
mod tests {
    use std::{fs::File, io::Read};

    use rarime_rust_sdk::{masters_certificate_pool::MastersCertificatePool, rfc::rfc5280};

    #[test]
    fn test_certificate_pool() {
        let mut file =
            File::open("tests/assets/masters.pem").expect("failed to open certificate masters");

        let mut masters_pems_data = String::new();
        file.read_to_string(&mut masters_pems_data)
            .expect("failed to read certificate masters data");

        let masters_pems = pem::parse_many(&masters_pems_data).expect("failed to parse raw pems");

        let mut master_certificates: Vec<rfc5280::Certificate> = vec![];
        for master_pem in &masters_pems {
            let master_pem_str = hex::encode(master_pem.contents());

            println!("master_pem_str: {master_pem_str}");

            let certificate: rfc5280::Certificate =
                asn1::parse_single(master_pem.contents()).expect("failed to parse master_pem");

            master_certificates.push(certificate);
        }

        let mut masters_certificate_pool = MastersCertificatePool::new();
        masters_certificate_pool.add_masters(master_certificates);
    }
}
