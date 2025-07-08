//! ECDSA Private Key PEM Generator from OTP
//!
//! This utility generates a unified SECP256R1 (P-256) key PEM from a private key stored in OTP
//! (One Time Programmable memory) using OpenSSL. It reads the private key from Raspberry Pi OTP
//! and outputs a complete PEM containing both the private and public key components.
//!
//! # Security Note
//! This tool handles cryptographic private keys. Ensure proper security practices when using:
//! - Use in secure environments only
//! - Never log or expose the output
//! - Clear memory after use where possible
//!
//! # Example Usage
//! ```bash
//! rpi-otp-ec-private-key
//! ```

use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use std::process::Command;

/// Custom error type for better error handling
#[derive(Debug)]
enum KeyGenError {
    /// OTP read error
    OtpError(String),
    /// Invalid hex string format
    InvalidHex(hex::FromHexError),
    /// Invalid private key length
    InvalidLength(usize),
    /// Invalid private key value (e.g., zero or too large)
    InvalidKeyValue,
    /// OpenSSL error
    OpenSslError(ErrorStack),
    /// UTF-8 conversion error
    Utf8Error(std::string::FromUtf8Error),
}

impl std::fmt::Display for KeyGenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyGenError::OtpError(e) => write!(f, "OTP read error: {e}"),
            KeyGenError::InvalidHex(e) => write!(f, "Invalid hex format: {e}"),
            KeyGenError::InvalidLength(len) => {
                write!(
                    f,
                    "Invalid private key length: {len} characters (expected 64)"
                )
            }
            KeyGenError::InvalidKeyValue => {
                write!(
                    f,
                    "Invalid private key value (must be non-zero and less than curve order)"
                )
            }
            KeyGenError::OpenSslError(e) => write!(f, "OpenSSL error: {e}"),
            KeyGenError::Utf8Error(e) => write!(f, "UTF-8 conversion error: {e}"),
        }
    }
}

impl std::error::Error for KeyGenError {}

impl From<hex::FromHexError> for KeyGenError {
    fn from(error: hex::FromHexError) -> Self {
        KeyGenError::InvalidHex(error)
    }
}

impl From<ErrorStack> for KeyGenError {
    fn from(error: ErrorStack) -> Self {
        KeyGenError::OpenSslError(error)
    }
}

impl From<std::string::FromUtf8Error> for KeyGenError {
    fn from(error: std::string::FromUtf8Error) -> Self {
        KeyGenError::Utf8Error(error)
    }
}

/// The expected length of a private key in hexadecimal characters (32 bytes * 2)
const PRIVATE_KEY_HEX_LENGTH: usize = 64;

/// OTP configuration constants
const OTP_ROW_COUNT: u32 = 8;
const OTP_ROW_OFFSET: u32 = 0;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match run() {
        Ok(pem_string) => {
            print!("{pem_string}");
            Ok(())
        }
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<String, KeyGenError> {
    // Read hex private key from OTP
    let hex_privkey = read_otp_key()?;
    process_hex_private_key(&hex_privkey)
}

/// Read private key from OTP using vcmailbox
fn read_otp_key() -> Result<String, KeyGenError> {
    // Calculate parameters for vcmailbox call
    let buffer_size = 8 + OTP_ROW_COUNT * 4;

    // Build vcmailbox command arguments
    let mut args = vec![
        "0x00030081".to_string(),
        buffer_size.to_string(),
        buffer_size.to_string(),
        OTP_ROW_OFFSET.to_string(),
        OTP_ROW_COUNT.to_string(),
    ];

    // Add zero padding (16 zeros as in the bash script)
    for _ in 0..16 {
        args.push("0".to_string());
    }

    // Execute vcmailbox command
    let output = Command::new("vcmailbox")
        .args(&args)
        .output()
        .map_err(|e| KeyGenError::OtpError(format!("Failed to execute vcmailbox: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(KeyGenError::OtpError(format!("vcmailbox failed: {stderr}")));
    }

    // Parse vcmailbox output
    let output_str = String::from_utf8(output.stdout)
        .map_err(|e| KeyGenError::OtpError(format!("Invalid UTF-8 in vcmailbox output: {e}")))?;

    // Process the output similar to the bash script
    // Remove 0x prefixes and extract fields 8 through (8 + ROW_COUNT - 1)
    let cleaned = output_str.replace("0x", "");
    let fields: Vec<&str> = cleaned.split_whitespace().collect();

    if fields.len() < (7 + OTP_ROW_COUNT as usize) {
        return Err(KeyGenError::OtpError(format!(
            "Insufficient fields in vcmailbox output: expected at least {}, got {} (vcmailbox typically returns 24 fields)",
            7 + OTP_ROW_COUNT,
            fields.len()
        )));
    }

    // Extract the key from fields 8 through (8 + ROW_COUNT - 1) (awk 1-indexed)
    // which corresponds to indices 7 through (7 + ROW_COUNT - 1) (Rust 0-indexed)
    let mut key_hex = String::new();
    for field in fields.iter().skip(7).take(OTP_ROW_COUNT as usize) {
        key_hex.push_str(field);
    }

    Ok(key_hex)
}

/// Process a hex private key string and return the PEM output
///
/// This function is separated from run() to make it testable without OTP dependencies
fn process_hex_private_key(hex_privkey: &str) -> Result<String, KeyGenError> {
    // Validate input length (64 characters for 32 bytes)
    if hex_privkey.len() != PRIVATE_KEY_HEX_LENGTH {
        return Err(KeyGenError::InvalidLength(hex_privkey.len()));
    }

    // Parse hex string to bytes
    let privkey_bytes = hex::decode(hex_privkey)?;

    // Validate private key is not zero
    if privkey_bytes.iter().all(|&b| b == 0) {
        return Err(KeyGenError::InvalidKeyValue);
    }

    // Generate ECDSA key pair from private key
    let ec_key = generate_keypair_from_private_key(&privkey_bytes)?;

    // Generate PEM-formatted unified key (contains both private and public key components)
    let pem_bytes = ec_key.private_key_to_pem()?;
    let pem_string = String::from_utf8(pem_bytes)?;

    Ok(pem_string)
}

/// Generate an ECDSA key pair from a private key using OpenSSL
///
/// This function creates a SECP256R1 (P-256) key pair from raw private key bytes.
/// It uses OpenSSL's EC_KEY_set_private_key equivalent and EC_POINT_mul to generate
/// the corresponding public key.
///
/// # Arguments
/// * `privkey_bytes` - Raw private key bytes (must be 32 bytes)
///
/// # Returns
/// * `Ok(EcKey)` - Valid ECDSA key pair containing both private and public components
/// * `Err(KeyGenError)` - If key generation fails
///
/// # Security Note
/// This function validates that the private key is within the valid range for
/// the SECP256R1 curve and that the generated key pair is mathematically correct.
fn generate_keypair_from_private_key(
    privkey_bytes: &[u8],
) -> Result<EcKey<openssl::pkey::Private>, KeyGenError> {
    // Validate private key is not zero
    if privkey_bytes.iter().all(|&b| b == 0) {
        return Err(KeyGenError::InvalidKeyValue);
    }

    // Create EC group for SECP256R1 (P-256)
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;

    // Convert private key bytes to BigNum
    let private_key_bn = BigNum::from_slice(privkey_bytes)?;

    // Validate private key is within curve order
    let mut ctx = BigNumContext::new()?;
    let mut order = BigNum::new()?;
    group.order(&mut order, &mut ctx)?;
    if private_key_bn >= order {
        return Err(KeyGenError::InvalidKeyValue);
    }

    // Generate the public key using EC_POINT_mul
    let ctx = BigNumContext::new()?;
    let mut pub_point = EcPoint::new(&group)?;

    // pub_point = private_key * generator (G)
    // This is equivalent to EC_POINT_mul(group, pub_point, private_key, NULL, NULL, ctx)
    pub_point.mul_generator(&group, &private_key_bn, &ctx)?;

    // Create EC key using from_private_components
    // This corresponds to EC_KEY_set_private_key and EC_KEY_set_public_key
    let ec_key = EcKey::from_private_components(&group, &private_key_bn, &pub_point)?;

    // Verify the key pair is valid
    ec_key.check_key()?;

    Ok(ec_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::PathBuf;
    use std::process::Command;

    /// Create a temporary file with unique name and return the path
    fn create_temp_file(prefix: &str, suffix: &str) -> PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let filename = format!("{prefix}{timestamp}{suffix}");
        std::env::temp_dir().join(filename)
    }

    #[test]
    fn test_process_hex_private_key_valid() {
        // Test with a known valid private key
        let private_key_hex = "304F2642C2F2E5712147613EA353D71116DA965B6B5FCFDCAEA3B39A96A5C40A";
        let result = process_hex_private_key(private_key_hex);

        assert!(result.is_ok());
        let pem_string = result.unwrap();

        // Verify PEM format
        assert!(pem_string.starts_with("-----BEGIN EC PRIVATE KEY-----"));
        assert!(pem_string.ends_with("-----END EC PRIVATE KEY-----\n"));

        // Verify it's not empty and contains base64 data
        let lines: Vec<&str> = pem_string.lines().collect();
        assert!(lines.len() >= 3);

        // Check the base64 content lines
        for line in &lines[1..lines.len() - 1] {
            assert!(!line.is_empty());
            assert!(
                line.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
            );
        }
    }

    #[test]
    fn test_asn1_parse_validation() {
        // Test with a known valid private key
        let private_key_hex = "304F2642C2F2E5712147613EA353D71116DA965B6B5FCFDCAEA3B39A96A5C40A";
        let result = process_hex_private_key(private_key_hex);
        assert!(result.is_ok());

        let pem_string = result.unwrap();

        // Write PEM to temporary file
        let temp_path = create_temp_file("test_key_", ".pem");
        let mut temp_file = File::create(&temp_path).expect("Failed to create temp file");
        temp_file
            .write_all(pem_string.as_bytes())
            .expect("Failed to write PEM to temp file");

        // Parse with openssl asn1parse
        let output = Command::new("openssl")
            .args(["asn1parse", "-i", "-in", temp_path.to_str().unwrap()])
            .output()
            .expect("Failed to execute openssl asn1parse");

        assert!(
            output.status.success(),
            "asn1parse failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let parse_output = String::from_utf8(output.stdout).expect("Invalid UTF-8 from asn1parse");

        // Verify ASN.1 structure contains our private key
        // Look for the OCTET STRING containing our private key
        assert!(parse_output.contains("OCTET STRING"));
        assert!(parse_output.contains("OBJECT            :prime256v1"));
        assert!(parse_output.contains("BIT STRING"));

        // Extract the hex dump of the private key from the ASN.1 parse output
        let lines: Vec<&str> = parse_output.lines().collect();
        let mut found_private_key = false;
        let mut extracted_hex = String::new();

        for line in &lines {
            if line.contains("OCTET STRING") && line.contains("[HEX DUMP]") {
                // Extract hex dump from lines following the OCTET STRING
                let hex_part = line.split("[HEX DUMP]:").nth(1);
                if let Some(hex) = hex_part {
                    extracted_hex = hex.trim().replace(":", "");
                    found_private_key = true;
                    break;
                }
            }
        }

        // If hex dump spans multiple lines, we need to collect it
        if !found_private_key {
            let mut collecting_hex = false;
            for line in &lines {
                if line.contains("OCTET STRING") && line.contains("[HEX DUMP]") {
                    collecting_hex = true;
                    let hex_part = line.split("[HEX DUMP]:").nth(1);
                    if let Some(hex) = hex_part {
                        extracted_hex.push_str(&hex.trim().replace(":", ""));
                    }
                } else if collecting_hex
                    && line
                        .trim()
                        .chars()
                        .all(|c| c.is_ascii_hexdigit() || c == ':')
                {
                    extracted_hex.push_str(&line.trim().replace(":", ""));
                } else if collecting_hex {
                    break;
                }
            }
            found_private_key = !extracted_hex.is_empty();
        }

        assert!(
            found_private_key,
            "Could not find private key in ASN.1 parse output"
        );

        // Convert to uppercase for comparison
        let extracted_upper = extracted_hex.to_uppercase();
        let input_upper = private_key_hex.to_uppercase();

        assert_eq!(
            extracted_upper, input_upper,
            "Private key mismatch: input={input_upper}, extracted={extracted_upper}"
        );

        // Clean up
        let _ = fs::remove_file(&temp_path);
    }

    #[test]
    fn test_pkeyutl_sign_verify() {
        // Test with a known valid private key
        let private_key_hex = "304F2642C2F2E5712147613EA353D71116DA965B6B5FCFDCAEA3B39A96A5C40A";
        let result = process_hex_private_key(private_key_hex);
        assert!(result.is_ok());

        let pem_string = result.unwrap();

        // Write PEM to temporary file
        let key_path = create_temp_file("test_key_", ".pem");
        let mut key_file = File::create(&key_path).expect("Failed to create temp key file");
        key_file
            .write_all(pem_string.as_bytes())
            .expect("Failed to write PEM to temp file");

        // Create test data to sign
        let test_data = b"Hello, World! This is a test message for ECDSA signing.";
        let data_path = create_temp_file("test_data_", ".txt");
        let mut data_file = File::create(&data_path).expect("Failed to create temp data file");
        data_file
            .write_all(test_data)
            .expect("Failed to write test data");

        // Create signature file path
        let sig_path = create_temp_file("test_sig_", ".sig");
        let pubkey_path = create_temp_file("test_pubkey_", ".pem");

        // Sign the data
        let sign_output = Command::new("openssl")
            .args([
                "pkeyutl",
                "-sign",
                "-inkey",
                key_path.to_str().unwrap(),
                "-in",
                data_path.to_str().unwrap(),
                "-out",
                sig_path.to_str().unwrap(),
            ])
            .output()
            .expect("Failed to execute openssl pkeyutl sign");

        assert!(
            sign_output.status.success(),
            "Signing failed: {}",
            String::from_utf8_lossy(&sign_output.stderr)
        );

        // Extract public key from the private key
        let pubkey_output = Command::new("openssl")
            .args([
                "pkey",
                "-in",
                key_path.to_str().unwrap(),
                "-pubout",
                "-out",
                pubkey_path.to_str().unwrap(),
            ])
            .output()
            .expect("Failed to extract public key");

        assert!(
            pubkey_output.status.success(),
            "Public key extraction failed: {}",
            String::from_utf8_lossy(&pubkey_output.stderr)
        );

        // Verify the signature using the public key
        let verify_output = Command::new("openssl")
            .args([
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                pubkey_path.to_str().unwrap(),
                "-in",
                data_path.to_str().unwrap(),
                "-sigfile",
                sig_path.to_str().unwrap(),
            ])
            .output()
            .expect("Failed to execute openssl pkeyutl verify");

        assert!(
            verify_output.status.success(),
            "Verification failed: {}",
            String::from_utf8_lossy(&verify_output.stderr)
        );

        let verify_result = String::from_utf8(verify_output.stdout).unwrap_or_default();
        assert!(
            verify_result.contains("Signature Verified Successfully")
                || verify_output.stderr.is_empty(),
            "Signature verification did not succeed: stdout={}, stderr={}",
            verify_result,
            String::from_utf8_lossy(&verify_output.stderr)
        );

        // Clean up temporary files
        let _ = fs::remove_file(&key_path);
        let _ = fs::remove_file(&data_path);
        let _ = fs::remove_file(&sig_path);
        let _ = fs::remove_file(&pubkey_path);
    }

    #[test]
    fn test_key_consistency_across_formats() {
        // Test that the same private key produces consistent results
        let private_key_hex = "304F2642C2F2E5712147613EA353D71116DA965B6B5FCFDCAEA3B39A96A5C40A";

        // Generate PEM multiple times
        let pem1 = process_hex_private_key(private_key_hex).unwrap();
        let pem2 = process_hex_private_key(private_key_hex).unwrap();

        // Should produce identical output
        assert_eq!(pem1, pem2, "PEM generation is not deterministic");

        // Write to temp file and extract public key
        let key_path1 = create_temp_file("test_key1_", ".pem");
        let mut key_file1 = File::create(&key_path1).expect("Failed to create temp key file");
        key_file1
            .write_all(pem1.as_bytes())
            .expect("Failed to write PEM to temp file");

        // Extract public key and verify it's consistent
        let pubkey_output1 = Command::new("openssl")
            .args(["pkey", "-in", key_path1.to_str().unwrap(), "-pubout"])
            .output()
            .expect("Failed to extract public key");

        assert!(pubkey_output1.status.success());

        // Generate another PEM and extract public key again
        let key_path2 = create_temp_file("test_key2_", ".pem");
        let mut key_file2 = File::create(&key_path2).expect("Failed to create temp key file");
        key_file2
            .write_all(pem2.as_bytes())
            .expect("Failed to write PEM to temp file");

        let pubkey_output2 = Command::new("openssl")
            .args(["pkey", "-in", key_path2.to_str().unwrap(), "-pubout"])
            .output()
            .expect("Failed to extract public key");

        assert!(pubkey_output2.status.success());

        // Public keys should be identical
        assert_eq!(
            pubkey_output1.stdout, pubkey_output2.stdout,
            "Public key extraction is not consistent"
        );

        // Clean up
        let _ = fs::remove_file(&key_path1);
        let _ = fs::remove_file(&key_path2);
    }

    #[test]
    fn test_process_hex_private_key_invalid_length() {
        // Test with incorrect length
        let short_key = "304F2642C2F2E5712147613EA353D71116DA965B6B5FCFDCAEA3B39A96A5C40";
        let result = process_hex_private_key(short_key);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            KeyGenError::InvalidLength(63)
        ));

        let long_key = "304F2642C2F2E5712147613EA353D71116DA965B6B5FCFDCAEA3B39A96A5C40AA";
        let result = process_hex_private_key(long_key);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            KeyGenError::InvalidLength(65)
        ));
    }

    #[test]
    fn test_process_hex_private_key_invalid_hex() {
        // Test with invalid hex characters
        let invalid_hex = "304F2642C2F2E5712147613EA353D71116DA965B6B5FCFDCAEA3B39A96A5C40G";
        let result = process_hex_private_key(invalid_hex);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), KeyGenError::InvalidHex(_)));
    }

    #[test]
    fn test_process_hex_private_key_zero_key() {
        // Test with zero private key
        let zero_key = "0000000000000000000000000000000000000000000000000000000000000000";
        let result = process_hex_private_key(zero_key);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), KeyGenError::InvalidKeyValue));
    }

    #[test]
    fn test_generate_keypair_from_private_key() {
        // Test with a known private key
        let private_key_hex = "304F2642C2F2E5712147613EA353D71116DA965B6B5FCFDCAEA3B39A96A5C40A";
        let private_key_bytes = hex::decode(private_key_hex).unwrap();

        let result = generate_keypair_from_private_key(&private_key_bytes);
        assert!(result.is_ok());

        let ec_key = result.unwrap();
        // Verify the key is valid
        assert!(ec_key.check_key().is_ok());
    }

    #[test]
    fn test_generate_keypair_zero_private_key() {
        // Test with zero private key (should fail with InvalidKeyValue)
        let zero_key = vec![0u8; 32];
        let result = generate_keypair_from_private_key(&zero_key);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), KeyGenError::InvalidKeyValue));
    }

    #[test]
    fn test_generate_keypair_invalid_private_key() {
        // Test with private key that's too large (all 0xFF bytes)
        let invalid_key = vec![0xFFu8; 32];
        let result = generate_keypair_from_private_key(&invalid_key);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), KeyGenError::InvalidKeyValue));
    }

    #[test]
    fn test_pem_output_format() {
        // Test that the PEM output has the correct format
        let private_key_hex = "304F2642C2F2E5712147613EA353D71116DA965B6B5FCFDCAEA3B39A96A5C40A";
        let private_key_bytes = hex::decode(private_key_hex).unwrap();

        let ec_key = generate_keypair_from_private_key(&private_key_bytes).unwrap();
        let pem_bytes = ec_key.private_key_to_pem().unwrap();
        let pem_string = String::from_utf8(pem_bytes).unwrap();

        // Check PEM format
        assert!(pem_string.starts_with("-----BEGIN EC PRIVATE KEY-----"));
        assert!(pem_string.ends_with("-----END EC PRIVATE KEY-----\n"));

        // Check that it contains base64 encoded data
        let lines: Vec<&str> = pem_string.lines().collect();
        assert!(lines.len() >= 3); // At least header, content, and footer

        // Verify that middle lines contain base64 data
        for line in &lines[1..lines.len() - 1] {
            assert!(
                line.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
            );
        }
    }

    #[test]
    fn test_hex_decode_validation() {
        // Test valid hex string
        let valid_hex = "304F2642C2F2E5712147613EA353D71116DA965B6B5FCFDCAEA3B39A96A5C40A";
        assert_eq!(hex::decode(valid_hex).unwrap().len(), 32);

        // Test invalid hex string
        let invalid_hex = "304F2642C2F2E5712147613EA353D71116DA965B6B5FCFDCAEA3B39A96A5C40G";
        assert!(hex::decode(invalid_hex).is_err());
    }

    #[test]
    fn test_private_key_length_validation() {
        // Test correct length
        let correct_length = "304F2642C2F2E5712147613EA353D71116DA965B6B5FCFDCAEA3B39A96A5C40A";
        assert_eq!(correct_length.len(), PRIVATE_KEY_HEX_LENGTH);

        // Test incorrect lengths
        let too_short = "304F2642C2F2E5712147613EA353D71116DA965B6B5FCFDCAEA3B39A96A5C40";
        assert_eq!(too_short.len(), PRIVATE_KEY_HEX_LENGTH - 1);

        let too_long = "304F2642C2F2E5712147613EA353D71116DA965B6B5FCFDCAEA3B39A96A5C40AA";
        assert_eq!(too_long.len(), PRIVATE_KEY_HEX_LENGTH + 1);
    }

    #[test]
    #[ignore] // Only run when explicitly requested: cargo test -- --ignored
    fn test_otp_key_reading() {
        // This test only works on a Raspberry Pi with OTP programmed
        // Run with: cargo test test_otp_key_reading -- --ignored

        // Test reading from OTP using rpi-otp-private-key
        let output = Command::new("rpi-otp-private-key").output();

        match output {
            Ok(output) => {
                if !output.status.success() {
                    println!(
                        "rpi-otp-private-key failed (this is expected on non-Pi systems): {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                    return;
                }

                let key_hex = String::from_utf8(output.stdout)
                    .expect("Invalid UTF-8 from rpi-otp-private-key")
                    .trim()
                    .to_string();

                // Validate the key format
                assert_eq!(
                    key_hex.len(),
                    PRIVATE_KEY_HEX_LENGTH,
                    "OTP key should be 64 hex characters, got: {}",
                    key_hex.len()
                );

                // Validate it's all hex characters
                assert!(
                    key_hex.chars().all(|c| c.is_ascii_hexdigit()),
                    "OTP key should contain only hex characters, got: {key_hex}"
                );

                // Test that our processing function can handle the OTP key
                let result = process_hex_private_key(&key_hex);
                assert!(
                    result.is_ok(),
                    "Failed to process OTP key: {:?}",
                    result.err()
                );

                let pem = result.unwrap();
                assert!(pem.starts_with("-----BEGIN EC PRIVATE KEY-----"));
                assert!(pem.ends_with("-----END EC PRIVATE KEY-----\n"));

                println!("Successfully processed OTP key and generated PEM");
            }
            Err(e) => {
                println!(
                    "Could not execute rpi-otp-private-key (this is expected on non-Pi systems): {e}"
                );
            }
        }
    }

    #[test]
    fn test_vcmailbox_output_parsing() {
        // Test parsing of vcmailbox output format
        // vcmailbox returns 24 fields, with our key data in fields 8-15 (awk 1-indexed, Rust indices 7-14)
        let mock_output = "0x00000000 0x00000000 0x00000000 0x00000000 0x00000000 0x00000000 0x00000000 0x304F2642 0xC2F2E571 0x2147613E 0xA353D711 0x16DA965B 0x6B5FCFDC 0xAEA3B39A 0x96A5C40A 0x00000000 0x00000000 0x00000000 0x00000000 0x00000000 0x00000000 0x00000000 0x00000000 0x00000000";

        // Simulate the processing logic from read_otp_key
        let cleaned = mock_output.replace("0x", "");
        let fields: Vec<&str> = cleaned.split_whitespace().collect();

        // Verify we have 24 fields as expected
        assert_eq!(fields.len(), 24, "vcmailbox should return 24 fields");
        assert!(fields.len() >= (7 + OTP_ROW_COUNT as usize));

        let mut key_hex = String::new();
        for field in fields.iter().skip(7).take(OTP_ROW_COUNT as usize) {
            key_hex.push_str(field);
        }

        // Should reconstruct the test key
        let expected = "304F2642C2F2E5712147613EA353D71116DA965B6B5FCFDCAEA3B39A96A5C40A";
        assert_eq!(key_hex.to_uppercase(), expected);

        // Test that the reconstructed key works
        let result = process_hex_private_key(&key_hex);
        assert!(result.is_ok());
    }
}
