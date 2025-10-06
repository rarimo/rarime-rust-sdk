pub fn bytes_to_string_array(bytes: &[u8]) -> Vec<String> {
    bytes.iter().map(|b| b.to_string()).collect()
}
