use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use sentrix_verifier_cli::canonical;

const PUBLIC_KEY: &str = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
const STORED_LINE: &str = concat!(
    r#"{"class":"normal","confidence":0.875,"features_hash":"2222222222222222222222222222222222222222222222222222222222222222","model_config_hash":"3333333333333333333333333333333333333333333333333333333333333333","model_id":"model-v1","node_id":"node-01","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","raw_csi_hash":"1111111111111111111111111111111111111111111111111111111111111111","record_hash":"ef5d7fe2153bd2653b9e8b2d19044498dfe07016a479a2c831d7e63c774777e8","seq":0,"signature":"872e9ac9e8f2c0fb3473ecfc85d852a622460ae3a9718a35376f21eaa16c547b6a35fb9633b8501b982cb7ab535631ad50ab9b7b58ed3d873a896b059318650f","top_shap":[],"ts_utc":"2026-07-13T12:00:00Z"}"#,
    "\n"
);

struct Fixture {
    directory: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "sentrix-verifier-test-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("create test directory");
        Self { directory }
    }

    fn write(&self, name: &str, contents: impl AsRef<[u8]>) -> PathBuf {
        let path = self.directory.join(name);
        fs::write(&path, contents).expect("write fixture");
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn verify(chain: &Path, key: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sentrix-verify"))
        .args(["chain"])
        .arg(chain)
        .args(["--pubkey"])
        .arg(key)
        .output()
        .expect("run sentrix-verify")
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn signed_chain(records: u64) -> Vec<u8> {
    let seed: [u8; 32] = std::array::from_fn(|index| u8::try_from(index).unwrap());
    let signing_key = SigningKey::from_bytes(&seed);
    assert_eq!(
        encode_hex(signing_key.verifying_key().as_bytes()),
        PUBLIC_KEY
    );
    let mut previous = "0".repeat(64);
    let mut chain = Vec::new();

    for seq in 0..records {
        let mut unsigned = Map::new();
        unsigned.insert("seq".to_owned(), json!(seq));
        unsigned.insert(
            "ts_utc".to_owned(),
            Value::String(format!("2026-07-13T12:00:{seq:02}Z")),
        );
        unsigned.insert("node_id".to_owned(), json!("node-01"));
        unsigned.insert("raw_csi_hash".to_owned(), json!("1".repeat(64)));
        unsigned.insert("features_hash".to_owned(), json!("2".repeat(64)));
        unsigned.insert("model_id".to_owned(), json!("model-v1"));
        unsigned.insert("model_config_hash".to_owned(), json!("3".repeat(64)));
        unsigned.insert("class".to_owned(), json!("normal"));
        unsigned.insert("confidence".to_owned(), json!(0.875));
        unsigned.insert("top_shap".to_owned(), json!([]));
        unsigned.insert("prev_hash".to_owned(), json!(previous));

        let record_bytes = canonical::serialize(&Value::Object(unsigned.clone())).unwrap();
        let hash = encode_hex(&Sha256::digest(&record_bytes));
        let signature = encode_hex(&signing_key.sign(&record_bytes).to_bytes());
        unsigned.insert("record_hash".to_owned(), json!(hash));
        unsigned.insert("signature".to_owned(), json!(signature));
        chain.extend(canonical::serialize(&Value::Object(unsigned)).unwrap());
        chain.push(b'\n');
        previous = hash;
    }
    chain
}

#[test]
fn spec_vector_is_byte_for_byte_compatible() {
    let fixture = Fixture::new();
    let chain = fixture.write("chain.jsonl", STORED_LINE);
    let key = fixture.write("public-key.hex", format!("{PUBLIC_KEY}\n"));

    let output = verify(&chain, &key);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("chain valid: 1 record(s)"));
}

#[test]
fn one_corrupt_historical_byte_reports_its_sequence() {
    let fixture = Fixture::new();
    let mut corrupted = signed_chain(3);
    let needle = b"normal";
    let offset = corrupted
        .windows(needle.len())
        .enumerate()
        .filter(|(_, window)| *window == needle)
        .nth(1)
        .map(|(offset, _)| offset)
        .expect("second record class value exists");
    corrupted[offset] = b'N';
    let chain = fixture.write("corrupt.jsonl", corrupted);
    let key = fixture.write("public-key.hex", PUBLIC_KEY);

    let output = verify(&chain, &key);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed at seq 1: record_hash mismatch"),
        "{stderr}"
    );
}

#[test]
fn missing_final_lf_reports_next_sequence() {
    let fixture = Fixture::new();
    let chain = fixture.write("unterminated.jsonl", STORED_LINE.trim_end_matches('\n'));
    let key = fixture.write("public-key.hex", PUBLIC_KEY);

    let output = verify(&chain, &key);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("seq 0: record is not LF-terminated"));
}

#[test]
fn altered_signature_is_rejected() {
    let fixture = Fixture::new();
    let mut corrupted = STORED_LINE.as_bytes().to_vec();
    let signature = b"872e9ac9";
    let offset = corrupted
        .windows(signature.len())
        .position(|window| window == signature)
        .expect("signature exists");
    corrupted[offset] = b'9';
    let chain = fixture.write("bad-signature.jsonl", corrupted);
    let key = fixture.write("public-key.hex", PUBLIC_KEY);

    let output = verify(&chain, &key);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("seq 0: Ed25519 signature verification failed")
    );
}
