use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use vestrix_verifier_cli::canonical;

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
            "vestrix-verifier-test-{}-{nonce}",
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
    Command::new(env!("CARGO_BIN_EXE_vestrix-verify"))
        .args(["chain"])
        .arg(chain)
        .args(["--pubkey"])
        .arg(key)
        .output()
        .expect("run vestrix-verify")
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unsigned_record(seq: u64, confidence: f64, previous: &str) -> Map<String, Value> {
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
    unsigned.insert("confidence".to_owned(), json!(confidence));
    unsigned.insert("top_shap".to_owned(), json!([]));
    unsigned.insert("prev_hash".to_owned(), json!(previous));
    unsigned
}

fn signed_chain(sequences: &[u64]) -> Vec<u8> {
    let seed: [u8; 32] = std::array::from_fn(|index| u8::try_from(index).unwrap());
    let signing_key = SigningKey::from_bytes(&seed);
    assert_eq!(
        encode_hex(signing_key.verifying_key().as_bytes()),
        PUBLIC_KEY
    );
    let mut previous = "0".repeat(64);
    let mut chain = Vec::new();

    for &seq in sequences {
        let mut unsigned = unsigned_record(seq, 0.875, &previous);
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
fn python_float_spec_vectors_match_hashes_and_signatures() {
    let seed: [u8; 32] = std::array::from_fn(|index| u8::try_from(index).unwrap());
    let signing_key = SigningKey::from_bytes(&seed);
    let cases = [
        (
            1.0,
            "427c3016848a90a8d4219a137b486fef785361379e5fbf1864451be59b4e67a0",
            concat!(
                "1587c4fe5d1499e72b931e8989d481b6d071e56506798e4f0bf9f3df60497d35",
                "ae95d5b8bb6caa963c7ed285430ef021eb103a3b7675b08dbb9a271f7924480b"
            ),
        ),
        (
            0.9532,
            "db55f077ce463a4ff1015aba74eadd3c5fd6ed31d78f0b77587c7b464f7872ed",
            concat!(
                "e8eadc6abfdd5cb34d2c5445a0083dbcd44bfb5e6cd11814d9a9ca814b0b7fbd",
                "1b20d0368b7b57b51565eb620c0f5dd531c6f689ffff791f5ec3457fddd0340b"
            ),
        ),
        (
            0.1 + 0.2,
            "3aa30e8f2ae3dbf23a617238837d97363be4aef9c9ff99a44d4c5ac44ca233d1",
            concat!(
                "e1b7ac82d66bfe177c1ba65a77b21ffde25e9e31d0d13075711df1256a85e940",
                "bfcb62ee7602dda55ab0b58c2e532c9537188dc8f168a7d20cdbecbc08926001"
            ),
        ),
        (
            0.00001,
            "10869621de6d71b59d6a112924e22ae7c152b3247e87695730300ba0bd7c8d27",
            concat!(
                "5c84aee62bd7bcf98dfe7e9c11bbdafd214869f8e142f6cd340910a67674d8a7c",
                "c1f1691d8b11c09d2d6a9ecfc185300fc0e5f2c6904e2e3f0c346e180b3a808"
            ),
        ),
    ];

    for (confidence, expected_hash, expected_signature) in cases {
        let unsigned = unsigned_record(0, confidence, &"0".repeat(64));
        let record_bytes = canonical::serialize(&Value::Object(unsigned)).unwrap();
        assert_eq!(encode_hex(&Sha256::digest(&record_bytes)), expected_hash);
        assert_eq!(
            encode_hex(&signing_key.sign(&record_bytes).to_bytes()),
            expected_signature
        );
    }
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
    let mut corrupted = signed_chain(&[0, 1, 2]);
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
fn validly_signed_hash_linked_sequence_gap_is_rejected_distinctly() {
    let fixture = Fixture::new();
    let chain = fixture.write("sequence-gap.jsonl", signed_chain(&[0, 1, 3]));
    let key = fixture.write("public-key.hex", PUBLIC_KEY);

    let output = verify(&chain, &key);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed at seq 2: sequence gap: found seq 3, expected 2"),
        "{stderr}"
    );
    assert!(!stderr.contains("hash link broken"), "{stderr}");
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

#[test]
fn anchor_nonzero_output_is_not_misrepresented_as_chain_corruption() {
    let fixture = Fixture::new();
    let missing_chain = fixture.directory.join("missing-chain.jsonl");
    let missing_proof = fixture.directory.join("missing-proof.ots");
    let output = Command::new(env!("CARGO_BIN_EXE_vestrix-verify"))
        .args(["anchor"])
        .arg(missing_chain)
        .args(["--ots-proof"])
        .arg(missing_proof)
        .output()
        .expect("run anchor command");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("anchor check incomplete"), "{stderr}");
    assert!(
        stderr.contains("does NOT mean the chain is corrupt or tampered"),
        "{stderr}"
    );
    assert!(
        stderr.contains("`chain` subcommand is the chain-integrity verdict"),
        "{stderr}"
    );
}
