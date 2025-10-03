#![allow(unused)]
use crate::RarimeError;
use base64::{Engine as _, engine::general_purpose};
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::{Decode, Encode};
use regex::Regex;
use x509_parser::asn1_rs::ToDer;
use x509_parser::oid_registry::*;
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

// Define the Master List structure similar to your Go code
#[derive(Debug)]
pub struct MasterList {
    pub version: i32,
    pub cert_list: Vec<Vec<u8>>, // Raw certificate data - each Vec<u8> is a certificate in DER format
}

pub struct LdifParser {
    pkd_regex: Regex,
}

// A wrapper that owns the certificate DER data
#[derive(Clone)]
pub struct OwnedCertificate {
    der_data: Vec<u8>,
}

impl<'a> OwnedCertificate {
    pub fn from_der(der_data: Vec<u8>) -> Result<Self, RarimeError> {
        // Validate that this is a valid certificate
        X509Certificate::from_der(&der_data)
            .map_err(|e| RarimeError::X509Error(format!("Invalid certificate DER data: {}", e)))?;

        Ok(OwnedCertificate { der_data })
    }

    pub fn from_pem(pem_bytes: Vec<u8>) -> Result<Self, RarimeError> {
        let content = str::from_utf8(&pem_bytes)?;
        let pem_obj = ::pem::parse(content)
            .map_err(|e| RarimeError::PemError(format!("Failed to parse PEM data: {}", e)))?;

        if pem_obj.tag() != "CERTIFICATE" {
            return Err(RarimeError::PemError(
                "PEM object is not a certificate".to_string(),
            ));
        }

        let der_data = pem_obj.contents().to_vec();
        Self::from_der(der_data)
    }

    pub fn parse(&'a self) -> Result<X509Certificate<'a>, RarimeError> {
        let (_, cert) = X509Certificate::from_der(&self.der_data)
            .map_err(|e| RarimeError::X509Error(format!("Failed to parse certificate: {}", e)))?;
        Ok(cert)
    }

    pub fn der_data(&self) -> &[u8] {
        &self.der_data
    }

    /// Find the master certificate that signed this slave certificate
    /// Returns the first matching master certificate from the provided list
    pub fn find_master_certificate(
        &self,
        masters: &[OwnedCertificate],
    ) -> Result<Option<OwnedCertificate>, RarimeError> {
        let slave_cert = self.parse()?;

        // Find candidates by matching issuer with subject
        let mut candidates = Vec::new();
        for master in masters {
            let master_cert = master.parse()?;

            // Check if issuer matches subject
            if slave_cert.issuer() == master_cert.subject() {
                candidates.push(master.clone());
            }
        }

        // Get the Authority Key Identifier from the slave certificate
        let slave_aki = self.extract_authority_key_identifier(&slave_cert)?;

        // Filter candidates by matching AKI with SKI
        for candidate in candidates {
            let master_cert = candidate.parse()?;

            // Get the Subject Key Identifier from the master certificate
            if let Ok(master_ski) = self.extract_subject_key_identifier(&master_cert)
                && slave_aki == master_ski
            {
                return Ok(Some(candidate));
            }
        }

        Ok(None)
    }

    /// Extract Authority Key Identifier from a certificate
    fn extract_authority_key_identifier(
        &self,
        cert: &X509Certificate,
    ) -> Result<Vec<u8>, RarimeError> {
        // Look for Authority Key Identifier extension
        for ext in cert.extensions() {
            if ext.oid == OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER
                && let ParsedExtension::AuthorityKeyIdentifier(aki) = ext.parsed_extension()
                && let Some(key_id) = &aki.key_identifier
            {
                return Ok(key_id.0.to_vec());
            }
        }

        Err(RarimeError::X509Error(
            "Authority Key Identifier extension not found".to_string(),
        ))
    }

    /// Extract Subject Key Identifier from a certificate
    fn extract_subject_key_identifier(
        &self,
        cert: &X509Certificate,
    ) -> Result<Vec<u8>, RarimeError> {
        // Look for Subject Key Identifier extension
        for ext in cert.extensions() {
            if ext.oid == OID_X509_EXT_SUBJECT_KEY_IDENTIFIER
                && let ParsedExtension::SubjectKeyIdentifier(ski) = ext.parsed_extension()
            {
                return Ok(ski.0.to_vec());
            }
        }

        Err(RarimeError::X509Error(
            "Subject Key Identifier extension not found".to_string(),
        ))
    }

    pub fn extract_raw_public_key(&self) -> Result<Vec<u8>, RarimeError> {
        // Extract the public key matching Go's ExtractPubKeys behavior
        let cert = self.parse()?;
        let public_key_info = cert.public_key();

        let parsed_public_key = match public_key_info.parsed() {
            Ok(parsed) => parsed,
            Err(e) => {
                return Err(RarimeError::X509Error(format!(
                    "Failed to parse public key: {}",
                    e
                )));
            }
        };

        let raw_key = match parsed_public_key {
            PublicKey::RSA(rsa_key) => {
                // Extract RSA modulus and normalize it
                let modulus: Vec<u8> = rsa_key.modulus.to_vec();
                Self::normalize_key_data(modulus)
            }
            PublicKey::EC(ec_point) => {
                // For EC keys, extract and normalize the point data
                let point_data = ec_point.data().to_vec();
                Self::normalize_ec_point(point_data)
            }
            PublicKey::DSA(dsa_key) => {
                // For DSA, normalize the public key data
                Self::normalize_key_data(dsa_key.to_vec())
            }
            PublicKey::GostR3410(gost_key) => {
                println!("GostR3410 public key found");
                // For GOST R 34.10, normalize the public key data
                Self::normalize_key_data(gost_key.to_vec())
            }
            PublicKey::GostR3410_2012(gost_key) => {
                println!("GostR3410-2012 public key found");
                // For GOST R 34.10-2012, normalize the public key data
                Self::normalize_key_data(gost_key.to_vec())
            }
            _ => {
                // For other public key types, get the raw subject public key bits
                let spki = &public_key_info.subject_public_key;
                let raw_bits = spki.to_der_vec_raw().map_err(|e| {
                    RarimeError::X509Error(format!("Failed to serialize public key: {}", e))
                })?;
                Self::normalize_key_data(raw_bits)
            }
        };

        Ok(raw_key)
    }

    /// Normalize key data by removing common prefixes and padding
    fn normalize_key_data(mut key_data: Vec<u8>) -> Vec<u8> {
        // Remove leading zero bytes (padding)
        while !key_data.is_empty() && key_data[0] == 0x00 {
            key_data.remove(0);
        }

        // If the key is now empty or too small, return as-is
        if key_data.len() < 2 {
            return key_data;
        }

        // Remove ASN.1 BIT STRING padding indicator if present
        // BIT STRING starts with 0x03, followed by length, then unused bits count (usually 0x00)
        if key_data.len() > 2 && key_data[0] == 0x03 {
            // Skip the BIT STRING tag and length parsing for now
            // This is a simplified approach - in practice you'd parse the length properly
            if key_data[2] == 0x00 {
                // Remove the first 3 bytes (tag, length, unused bits)
                key_data = key_data[3..].to_vec();
            }
        }

        // Remove any additional leading zeros after BIT STRING removal
        while !key_data.is_empty() && key_data[0] == 0x00 {
            key_data.remove(0);
        }

        key_data
    }

    /// Normalize EC point data by handling various point formats
    fn normalize_ec_point(mut point_data: Vec<u8>) -> Vec<u8> {
        // Remove leading zero bytes
        while !point_data.is_empty() && point_data[0] == 0x00 {
            point_data.remove(0);
        }

        if point_data.is_empty() {
            return point_data;
        }

        // Handle uncompressed point format (0x04 prefix)
        if point_data[0] == 0x04 {
            // Remove the 0x04 prefix for uncompressed points
            point_data = point_data[1..].to_vec();

            // For uncompressed points, the data is X || Y coordinates
            // Each coordinate might have leading zeros that need normalization
            if point_data.len().is_multiple_of(2) {
                let coord_len = point_data.len() / 2;
                let mut x_coord = point_data[..coord_len].to_vec();
                let mut y_coord = point_data[coord_len..].to_vec();

                // Remove leading zeros from each coordinate
                while !x_coord.is_empty() && x_coord[0] == 0x00 {
                    x_coord.remove(0);
                }
                while !y_coord.is_empty() && y_coord[0] == 0x00 {
                    y_coord.remove(0);
                }

                // Reconstruct the point data
                let mut normalized = Vec::new();
                normalized.extend_from_slice(&x_coord);
                normalized.extend_from_slice(&y_coord);
                return normalized;
            }
        }

        // Handle compressed point formats (0x02, 0x03 prefixes)
        if point_data[0] == 0x02 || point_data[0] == 0x03 {
            // For compressed points, remove the compression indicator
            // and normalize the X coordinate
            let mut x_coord = point_data[1..].to_vec();
            while !x_coord.is_empty() && x_coord[0] == 0x00 {
                x_coord.remove(0);
            }
            return x_coord;
        }

        // If no recognized format, just remove leading zeros
        while !point_data.is_empty() && point_data[0] == 0x00 {
            point_data.remove(0);
        }

        point_data
    }
}

impl LdifParser {
    pub fn new() -> Self {
        Self {
            pkd_regex: Regex::new(r"(?s)pkdMasterListContent:: (.*?)\n\n").unwrap(),
        }
    }

    pub fn parse(&'_ self, data: &[u8]) -> Result<Vec<X509Certificate<'_>>, RarimeError> {
        let content = str::from_utf8(data)?;
        self.parse_string(content)
    }

    pub fn parse_string(&'_ self, content: &str) -> Result<Vec<X509Certificate<'_>>, RarimeError> {
        let owned_certs = self.parse_to_owned_certificates(content)?;
        let mut certificates = Vec::new();

        for owned_cert in owned_certs {
            // Use Box::leak to make the certificate data live for the entire program duration
            // This is necessary because X509Certificate needs to borrow from the DER data
            let static_data: &'static [u8] = Box::leak(owned_cert.der_data.into_boxed_slice());
            match X509Certificate::from_der(static_data) {
                Ok((_, cert)) => certificates.push(cert),
                Err(e) => eprintln!("Warning: Failed to parse certificate: {}", e),
            }
        }

        if certificates.is_empty() {
            return Err(RarimeError::NoCertificatesFound);
        }

        Ok(certificates)
    }

    pub fn parse_to_owned_certificates(
        &self,
        content: &str,
    ) -> Result<Vec<OwnedCertificate>, RarimeError> {
        let mut all_certificates = Vec::new();

        // Find all pkdMasterListContent entries - each match is a master list
        let mut master_lists = Vec::new();

        for captures in self.pkd_regex.captures_iter(content) {
            if let Some(base64_match) = captures.get(1) {
                let base64_data = base64_match.as_str();

                // Remove newline + space patterns (continuation lines)
                let clean_base64 = base64_data.replace("\n ", "");

                // Decode base64
                let decoded = general_purpose::STANDARD.decode(clean_base64.trim())?;

                // println!("Decoded length: {}", decoded.len());
                // println!(
                //     "First 32 bytes: {:?}",
                //     &decoded[..std::cmp::min(32, decoded.len())]
                // );

                // Parse this PKD entry as a master list
                match self.parse_pkd_entry(&decoded) {
                    Ok(master_list) => {
                        master_lists.push(master_list);
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to parse PKD entry: {} {}", e, clean_base64);
                    }
                }
            }
        }

        // Convert all master lists to owned certificates
        for master_list in master_lists {
            for cert_data in master_list.cert_list {
                match OwnedCertificate::from_der(cert_data) {
                    Ok(cert) => all_certificates.push(cert),
                    Err(e) => eprintln!("Warning: Failed to create certificate from DER: {}", e),
                }
            }
        }

        if all_certificates.is_empty() {
            return Err(RarimeError::NoCertificatesFound);
        }

        Ok(all_certificates)
    }

    fn parse_pkd_entry(&self, data: &[u8]) -> Result<MasterList, RarimeError> {
        // Try to parse as strict DER first
        match self.parse_pkd_entry_der(data) {
            Ok(master_list) => Ok(master_list),
            Err(der_error) => {
                // If DER parsing fails, try BER parsing as fallback
                match self.parse_pkd_entry_ber(data) {
                    Ok(master_list) => Ok(master_list),
                    Err(ber_error) => {
                        // If both fail, return the original DER error
                        Err(RarimeError::DerError(format!(
                            "Failed to parse PKD entry as both DER and BER. DER error: {}. BER error: {}",
                            der_error, ber_error
                        )))
                    }
                }
            }
        }
    }

    fn parse_pkd_entry_der(&self, data: &[u8]) -> Result<MasterList, RarimeError> {
        // Parse the ContentInfo structure
        let content_info = ContentInfo::from_der(data)
            .map_err(|e| RarimeError::DerError(format!("Failed to parse ContentInfo: {}", e)))?;

        // Extract SignedData from the content
        let content_der = content_info
            .content
            .to_der()
            .map_err(|e| RarimeError::DerError(format!("Failed to serialize content: {}", e)))?;

        let signed_data = SignedData::from_der(&content_der)
            .map_err(|e| RarimeError::DerError(format!("Failed to parse SignedData: {}", e)))?;

        // Get the encapsulated content (the master list)
        if let Some(econtent) = &signed_data.encap_content_info.econtent {
            // Get the raw bytes from econtent
            let encap_data = econtent.to_der().map_err(|e| {
                RarimeError::DerError(format!("Failed to serialize econtent: {}", e))
            })?;

            // Parse the ASN.1 structure to extract the master list
            let master_list = self.parse_encap_data_with_asn1(&encap_data)?;

            Ok(master_list)
        } else {
            Err(RarimeError::DerError(
                "No encapsulated content found in SignedData".to_string(),
            ))
        }
    }

    fn parse_pkd_entry_ber(&self, data: &[u8]) -> Result<MasterList, RarimeError> {
        // For BER encoded data, we need to manually parse the structure
        // This is a simplified approach that looks for certificates directly in the data
        use ::der_parser::ber::parse_ber_sequence;

        // Try to parse the top-level sequence
        match parse_ber_sequence(data) {
            Ok((_, _)) => {
                // Look for embedded certificates in the parsed structure
                let master_list = self.extract_certificates_from_ber_data(data)?;
                Ok(master_list)
            }
            Err(e) => Err(RarimeError::DerError(format!(
                "Failed to parse BER sequence: {}",
                e
            ))),
        }
    }

    fn extract_certificates_from_ber_data(&self, data: &[u8]) -> Result<MasterList, RarimeError> {
        // Scan through the data looking for certificate patterns
        let mut cert_list = Vec::new();
        let mut pos = 0;
        let version = 0i32; // Default version

        while pos < data.len() {
            if pos + 4 < data.len() && data[pos] == 0x30 {
                // Found a potential certificate (SEQUENCE)
                if let Some(cert_der) = self.extract_certificate_at_position(data, pos) {
                    // Validate it's actually a certificate
                    if let Ok((_, _)) = X509Certificate::from_der(&cert_der) {
                        let cert_len = cert_der.len();
                        cert_list.push(cert_der);
                        pos += cert_len;
                    } else {
                        pos += 1;
                    }
                } else {
                    pos += 1;
                }
            } else {
                pos += 1;
            }
        }

        if cert_list.is_empty() {
            return Err(RarimeError::NoCertificatesFound);
        }

        Ok(MasterList { version, cert_list })
    }

    fn parse_encap_data_with_asn1(&self, data: &[u8]) -> Result<MasterList, RarimeError> {
        // The encapsulated data might be wrapped in an OCTET STRING
        let actual_data = if data.len() > 2 && data[0] == 0x04 {
            // OCTET STRING tag (0x04)

            let length_byte = data[1];
            if length_byte & 0x80 == 0 {
                // Short form length
                let content_length = length_byte as usize;
                if data.len() >= 2 + content_length {
                    &data[2..2 + content_length]
                } else {
                    return Err(RarimeError::DerError(
                        "Invalid OCTET STRING length".to_string(),
                    ));
                }
            } else {
                // Long form length - more complex parsing needed
                let length_bytes = (length_byte & 0x7f) as usize;
                if length_bytes == 0 || length_bytes > 4 || data.len() < 2 + length_bytes {
                    return Err(RarimeError::DerError(
                        "Invalid OCTET STRING length encoding".to_string(),
                    ));
                }

                let mut content_length = 0usize;
                for i in 0..length_bytes {
                    content_length = (content_length << 8) | data[2 + i] as usize;
                }

                let start = 2 + length_bytes;
                if data.len() >= start + content_length {
                    &data[start..start + content_length]
                } else {
                    return Err(RarimeError::DerError(
                        "Invalid OCTET STRING content length".to_string(),
                    ));
                }
            }
        } else {
            data
        };

        // Parse the sequence elements step by step
        let mut version = 0i32;
        let mut cert_list = Vec::new();

        // Try to parse version and certificates from the sequence
        // This is a simplified approach - we'll scan for X.509 certificates
        let mut pos = 0;
        let mut found_version = false;

        // First, try to find version (INTEGER)
        while pos < actual_data.len() && !found_version {
            if actual_data[pos] == 0x02 {
                // INTEGER tag
                if pos + 1 < actual_data.len() {
                    let length = actual_data[pos + 1] as usize;
                    if length > 0 && length <= 4 && pos + 2 + length <= actual_data.len() {
                        let mut ver = 0i32;
                        for i in 0..length {
                            ver = (ver << 8) | actual_data[pos + 2 + i] as i32;
                        }
                        version = ver;
                        found_version = true;

                        pos += 2 + length;
                    } else {
                        pos += 1;
                    }
                } else {
                    pos += 1;
                }
            } else {
                pos += 1;
            }
        }

        // Now scan for certificates (SEQUENCE starting with 0x30)
        pos = 0;
        while pos < actual_data.len() {
            if actual_data[pos] == 0x30 {
                // Found a potential certificate (SEQUENCE)
                if let Some(cert_der) = self.extract_certificate_at_position(actual_data, pos) {
                    // Validate it's actually a certificate
                    if let Ok((_, _)) = X509Certificate::from_der(&cert_der) {
                        let cert_len = cert_der.len();
                        cert_list.push(cert_der);
                        pos += cert_len;
                    } else {
                        pos += 1;
                    }
                } else {
                    pos += 1;
                }
            } else {
                pos += 1;
            }
        }

        Ok(MasterList { version, cert_list })
    }

    fn extract_certificate_at_position(&self, data: &[u8], pos: usize) -> Option<Vec<u8>> {
        if pos + 2 >= data.len() {
            return None;
        }

        // Parse the length field of the SEQUENCE
        let length_byte = data[pos + 1];
        if length_byte & 0x80 == 0 {
            // Short form length
            let content_length = length_byte as usize;
            let total_length = 2 + content_length;
            if pos + total_length <= data.len() {
                return Some(data[pos..pos + total_length].to_vec());
            }
        } else {
            // Long form length
            let length_bytes = (length_byte & 0x7f) as usize;
            if length_bytes == 0 || length_bytes > 4 || pos + 2 + length_bytes > data.len() {
                return None;
            }

            let mut content_length = 0usize;
            for i in 0..length_bytes {
                content_length = (content_length << 8) | data[pos + 2 + i] as usize;
            }

            let total_length = 2 + length_bytes + content_length;
            if pos + total_length <= data.len() {
                return Some(data[pos..pos + total_length].to_vec());
            }
        }

        None
    }
}

pub struct PemParser;

impl PemParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse PEM-encoded certificates from bytes
    pub fn parse(&self, data: &[u8]) -> Result<Vec<OwnedCertificate>, RarimeError> {
        let content = str::from_utf8(data)?;
        self.parse_string(content)
    }

    /// Parse PEM-encoded certificates from a string
    pub fn parse_string(&self, content: &str) -> Result<Vec<OwnedCertificate>, RarimeError> {
        let pem_objects = ::pem::parse_many(content)
            .map_err(|e| RarimeError::PemError(format!("Failed to parse PEM data: {}", e)))?;

        let mut certificates = Vec::new();

        for pem_obj in pem_objects {
            // Only process CERTIFICATE objects
            if pem_obj.tag() == "CERTIFICATE" {
                // The contents are already DER-encoded
                let der_data = pem_obj.contents().to_vec();

                // Validate that this is a valid certificate
                match OwnedCertificate::from_der(der_data) {
                    Ok(cert) => certificates.push(cert),
                    Err(e) => {
                        eprintln!("Warning: Failed to parse certificate from PEM: {}", e);
                    }
                }
            }
        }

        if certificates.is_empty() {
            return Err(RarimeError::NoCertificatesFound);
        }

        Ok(certificates)
    }
}

impl Default for LdifParser {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for PemParser {
    fn default() -> Self {
        Self::new()
    }
}
