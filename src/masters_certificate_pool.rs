use crate::rfc::rfc5280;

pub struct MastersCertificatePool<'a> {
    pub masters: Vec<rfc5280::Certificate<'a>>,
}

impl<'a> MastersCertificatePool<'a> {
    pub fn new() -> Self {
        Self { masters: vec![] }
    }

    pub fn add_masters(&mut self, mut certificates_to_add: Vec<rfc5280::Certificate<'a>>) {
        self.masters.append(&mut certificates_to_add);
    }

    pub fn find_master(&self, slave: rfc5280::Certificate<'a>) {
        let signature_algorithm = slave.signature_algorithm.algorithm;
        let signature = hex::encode(slave.signature_value.as_bytes());

        println!("signature_algorithm: {signature_algorithm}");
        println!("signature: {signature}");
    }
}
