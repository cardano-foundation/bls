use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::NamedTempFile;

// ------------------------------------------------------------------
// SMT command tests
// ------------------------------------------------------------------

#[test]
fn smt_insert_and_digest() {
    let state_file = NamedTempFile::new().unwrap();

    // Insert items
    let mut cmd_insert = Command::cargo_bin("smt").unwrap();
    cmd_insert
        .arg("insert")
        .arg("--depth")
        .arg("2")
        .arg("--items")
        .arg("1 100,2 200")
        .arg("--state")
        .arg(state_file.path());
    cmd_insert
        .assert()
        .success()
        .stderr(predicate::str::contains("Inserted"))
        .stderr(predicate::str::contains("digest:"));

    // Verify state file was written and contains valid JSON
    let state_text = fs::read_to_string(state_file.path()).unwrap();
    let state_json: serde_json::Value = serde_json::from_str(&state_text).unwrap();
    assert_eq!(state_json["depth"], 2);
    assert!(
        state_json["digest"].as_str().unwrap().len() > 0,
        "digest should be non-empty"
    );

    // Print digest
    let mut cmd_digest = Command::cargo_bin("smt").unwrap();
    cmd_digest
        .arg("digest")
        .arg("--state")
        .arg(state_file.path());
    cmd_digest
        .assert()
        .success()
        .stdout(predicate::str::contains(
            state_json["digest"].as_str().unwrap(),
        ));
}

#[test]
fn smt_insert_raw_commitments() {
    let state_file = NamedTempFile::new().unwrap();

    let mut cmd = Command::cargo_bin("smt").unwrap();
    cmd.arg("insert")
        .arg("--depth")
        .arg("2")
        .arg("--items")
        .arg("10,20,30")
        .arg("--state")
        .arg(state_file.path());

    cmd.assert()
        .success()
        .stderr(predicate::str::contains("Inserted"));

    let state_text = fs::read_to_string(state_file.path()).unwrap();
    let state_json: serde_json::Value = serde_json::from_str(&state_text).unwrap();
    assert_eq!(state_json["depth"], 2);
    assert!(state_json["digest"].as_str().unwrap().len() > 0);
}

#[test]
fn smt_path_prints_digest() {
    let state_file = NamedTempFile::new().unwrap();

    // First insert so we have a state file
    let mut cmd_insert = Command::cargo_bin("smt").unwrap();
    cmd_insert
        .arg("insert")
        .arg("--depth")
        .arg("2")
        .arg("--items")
        .arg("42")
        .arg("--state")
        .arg(state_file.path());
    cmd_insert.assert().success();

    // Now query path for the inserted leaf
    let mut cmd_path = Command::cargo_bin("smt").unwrap();
    cmd_path
        .arg("path")
        .arg("--state")
        .arg(state_file.path())
        .arg("--leaf")
        .arg("42");
    cmd_path
        .assert()
        .success()
        .stdout(predicate::str::contains("digest:"))
        .stdout(predicate::str::contains("level 0:"));
}

#[test]
fn smt_missing_state_file() {
    let mut cmd = Command::cargo_bin("smt").unwrap();
    cmd.arg("digest")
        .arg("--state")
        .arg("/nonexistent/path/smt.json");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("failed to read state file"));
}

#[test]
fn smt_verify_valid_path() {
    let state_file = NamedTempFile::new().unwrap();

    // Insert raw commitments
    let mut cmd_insert = Command::cargo_bin("smt").unwrap();
    cmd_insert
        .arg("insert")
        .arg("--depth")
        .arg("2")
        .arg("--items")
        .arg("10,20")
        .arg("--state")
        .arg(state_file.path());
    cmd_insert.assert().success();

    // Verify path for a known commitment
    let mut cmd_verify = Command::cargo_bin("smt").unwrap();
    cmd_verify
        .arg("verify")
        .arg("--state")
        .arg(state_file.path())
        .arg("--leaf")
        .arg("10");
    cmd_verify
        .assert()
        .success()
        .stdout(predicate::str::contains("VALID"));
}

#[test]
fn smt_verify_invalid_path() {
    let state_file = NamedTempFile::new().unwrap();

    let mut cmd_insert = Command::cargo_bin("smt").unwrap();
    cmd_insert
        .arg("insert")
        .arg("--depth")
        .arg("2")
        .arg("--items")
        .arg("10,20")
        .arg("--state")
        .arg(state_file.path());
    cmd_insert.assert().success();

    // Verify path for a leaf NOT in the tree
    let mut cmd_verify = Command::cargo_bin("smt").unwrap();
    cmd_verify
        .arg("verify")
        .arg("--state")
        .arg(state_file.path())
        .arg("--leaf")
        .arg("999");
    cmd_verify
        .assert()
        .success()
        .stdout(predicate::str::contains("INVALID"))
        .stdout(predicate::str::contains("not found in tree"));
}

#[test]
fn smt_export_creates_input_json() {
    let state_file = NamedTempFile::new().unwrap();
    let input_file = NamedTempFile::new().unwrap();

    let mut cmd_insert = Command::cargo_bin("smt").unwrap();
    cmd_insert
        .arg("insert")
        .arg("--depth")
        .arg("2")
        .arg("--items")
        .arg("1 100,2 200")
        .arg("--state")
        .arg(state_file.path());
    cmd_insert.assert().success();

    let mut cmd_export = Command::cargo_bin("smt").unwrap();
    cmd_export
        .arg("export")
        .arg("--state")
        .arg(state_file.path())
        .arg("--nullifier")
        .arg("1")
        .arg("--out")
        .arg(input_file.path());
    cmd_export
        .assert()
        .success()
        .stderr(predicate::str::contains("Witness input written to"));

    let input_text = fs::read_to_string(input_file.path()).unwrap();
    let input_json: serde_json::Value = serde_json::from_str(&input_text).unwrap();
    assert!(input_json["digest"].as_str().unwrap().len() > 0);
    assert_eq!(input_json["nullifier"], "1");
    assert!(input_json["nonce"].as_str().unwrap().len() > 0);
}

#[test]
fn smt_insert_from_transcript_file() {
    let state_file = NamedTempFile::new().unwrap();
    let transcript_file = NamedTempFile::new().unwrap();

    fs::write(
        transcript_file.path(),
        "1 100\n2 200\n3 300\n",
    ).unwrap();

    let mut cmd = Command::cargo_bin("smt").unwrap();
    cmd.arg("insert")
        .arg("--depth")
        .arg("2")
        .arg("--transcript")
        .arg(transcript_file.path())
        .arg("--state")
        .arg(state_file.path());

    cmd.assert()
        .success()
        .stderr(predicate::str::contains("Inserted 3 item(s) into SMT"));

    let state_text = fs::read_to_string(state_file.path()).unwrap();
    let state_json: serde_json::Value = serde_json::from_str(&state_text).unwrap();
    assert_eq!(state_json["depth"], 2);
    assert!(state_json["digest"].as_str().unwrap().len() > 0);
    assert_eq!(state_json["items"].as_array().unwrap().len(), 3);
}

#[test]
fn smt_leaf_computes_mimc_commitment() {
    // Known value cross-checked against the in-Python `multi_mimc7`:
    //   leaf([1,2,3,4,5,6]) = 16125901014162640262929794406980070057269520862577327302420520588219082534074
    let mut cmd = Command::cargo_bin("smt").unwrap();
    cmd.arg("leaf")
        .arg("--items")
        .arg("1,2,3,4,5,6");
    cmd.assert()
        .success()
        .stdout("16125901014162640262929794406980070057269520862577327302420520588219082534074\n");
}

#[test]
fn smt_leaf_json_output() {
    let mut cmd = Command::cargo_bin("smt").unwrap();
    cmd.arg("leaf")
        .arg("--items")
        .arg("1,2,3,4,5,6")
        .arg("--json");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("\"leaf\":\"16125901014162640262929794406980070057269520862577327302420520588219082534074\""));
}

#[test]
fn smt_leaf_rejects_wrong_item_count() {
    let mut cmd = Command::cargo_bin("smt").unwrap();
    cmd.arg("leaf")
        .arg("--items")
        .arg("1,2,3");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("expected exactly 6 field elements"));
}

// Fixed-seed test key from test_smt_simple.py (PyNaCl SigningKey with seed
// a54554e8...). The expected values are cross-checked against the Python
// Ed25519 math that previously lived in gen_smt_input.py.
const TEST_PK_HEX: &str = "6f1aefc3c897385b1f65d663ab3bddc449ed2c47221c6b6c8a0650eb9791fd15";
const TEST_XSK_HEX: &str = "07ac47da43d59cdb54f1478e9b4423017a50ee1b9395abc485f6fb503e636c76";
const TEST_LEAF: &str = "27961596706507914158623253209230753532538365366985401348575292741777463643887";

#[test]
fn smt_key_computes_witness_data() {
    let mut cmd = Command::cargo_bin("smt").unwrap();
    cmd.arg("key")
        .arg("--vk")
        .arg(TEST_PK_HEX)
        .arg("--xsk")
        .arg(TEST_XSK_HEX);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("MiMC leaf:"))
        .stdout(predicate::str::contains(TEST_LEAF))
        .stdout(predicate::str::contains("sk bits:     255"));
}

#[test]
fn smt_key_json_output_matches_python() {
    let mut cmd = Command::cargo_bin("smt").unwrap();
    cmd.arg("key")
        .arg("--vk")
        .arg(TEST_PK_HEX)
        .arg("--xsk")
        .arg(TEST_XSK_HEX)
        .arg("--json");
    let out = cmd.output().unwrap();
    assert!(out.status.success());
    let key: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();

    assert_eq!(key["vk"], TEST_PK_HEX);
    assert_eq!(key["leaf"], TEST_LEAF);
    assert_eq!(key["PointA"][0], serde_json::json!(["2399581124961290996361902", "2009628761619076154966489", "30339864015231051762033261"]));
    assert_eq!(key["PointA"][1], serde_json::json!(["27073905468528505689938543", "1294987332572946710223646", "6646221664223807267347143"]));
    assert_eq!(key["PointA"][2], serde_json::json!(["1", "0", "0"]));
    assert_eq!(key["PointA"][3], serde_json::json!(["13481680252249361442501028", "27476611588222441719674700", "30361843228047889970922690"]));
    assert_eq!(key["A"].as_array().unwrap().len(), 256);
    assert_eq!(key["sk"].as_array().unwrap().len(), 255);
    assert_eq!(key["A"][0], "1");
}

#[test]
fn smt_key_rejects_bad_hex() {
    let mut cmd = Command::cargo_bin("smt").unwrap();
    cmd.arg("key")
        .arg("--vk")
        .arg("zz")
        .arg("--xsk")
        .arg(TEST_XSK_HEX);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("invalid --vk hex"));

    let mut cmd = Command::cargo_bin("smt").unwrap();
    cmd.arg("key")
        .arg("--vk")
        .arg(TEST_PK_HEX)
        .arg("--xsk")
        .arg("00"); // 1 byte, not 32
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("--xsk must be exactly 32 bytes"));
}

#[test]
fn smt_cardano_input_assembles_full_input() {
    let state_file = NamedTempFile::new().unwrap();
    let key_file = NamedTempFile::new().unwrap();
    let input_file = NamedTempFile::new().unwrap();

    let mut cmd_key = Command::cargo_bin("smt").unwrap();
    cmd_key
        .arg("key")
        .arg("--vk")
        .arg(TEST_PK_HEX)
        .arg("--xsk")
        .arg(TEST_XSK_HEX)
        .arg("--json");
    let key_out = cmd_key.output().unwrap();
    assert!(key_out.status.success());
    fs::write(key_file.path(), &key_out.stdout).unwrap();

    let mut cmd_insert = Command::cargo_bin("smt").unwrap();
    cmd_insert
        .arg("insert")
        .arg("--depth")
        .arg("2")
        .arg("--items")
        .arg(format!("{TEST_LEAF},12345,67890"))
        .arg("--state")
        .arg(state_file.path());
    cmd_insert.assert().success();

    let mut cmd_input = Command::cargo_bin("smt").unwrap();
    cmd_input
        .arg("cardano-input")
        .arg("--state")
        .arg(state_file.path())
        .arg("--key")
        .arg(key_file.path())
        .arg("--out")
        .arg(input_file.path());
    cmd_input
        .assert()
        .success()
        .stderr(predicate::str::contains("Witness input written to"));

    let input_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(input_file.path()).unwrap()).unwrap();
    assert_eq!(input_json["A"].as_array().unwrap().len(), 256);
    assert_eq!(input_json["sk"].as_array().unwrap().len(), 255);
    assert_eq!(input_json["PointA"][0][0], "2399581124961290996361902");
    assert_eq!(input_json["smt_siblings"].as_array().unwrap().len(), 2);
    assert_eq!(input_json["smt_directions"].as_array().unwrap().len(), 2);
    assert!(input_json["smt_root"].as_str().unwrap().len() > 0);

    // Re-hashing the path must reproduce the stored root: the witness root
    // is the tree digest itself.
    let mut cmd_digest = Command::cargo_bin("smt").unwrap();
    cmd_digest
        .arg("digest")
        .arg("--state")
        .arg(state_file.path());
    let digest_out = cmd_digest.output().unwrap();
    assert!(digest_out.status.success());
    let digest = String::from_utf8(digest_out.stdout).unwrap().trim().to_string();
    assert_eq!(input_json["smt_root"], digest);
}

#[test]
fn smt_cardano_input_requires_sk_bits() {
    let state_file = NamedTempFile::new().unwrap();
    let key_file = NamedTempFile::new().unwrap();
    let input_file = NamedTempFile::new().unwrap();

    // key record without --xsk (no `sk` bits)
    let mut cmd_key = Command::cargo_bin("smt").unwrap();
    cmd_key
        .arg("key")
        .arg("--vk")
        .arg(TEST_PK_HEX)
        .arg("--json");
    let key_out = cmd_key.output().unwrap();
    assert!(key_out.status.success());
    let key_json: serde_json::Value = serde_json::from_slice(&key_out.stdout).unwrap();
    assert!(key_json.get("sk").is_none());
    fs::write(key_file.path(), &key_out.stdout).unwrap();

    let mut cmd_insert = Command::cargo_bin("smt").unwrap();
    cmd_insert
        .arg("insert")
        .arg("--depth")
        .arg("2")
        .arg("--items")
        .arg(TEST_LEAF)
        .arg("--state")
        .arg(state_file.path());
    cmd_insert.assert().success();

    let mut cmd_input = Command::cargo_bin("smt").unwrap();
    cmd_input
        .arg("cardano-input")
        .arg("--state")
        .arg(state_file.path())
        .arg("--key")
        .arg(key_file.path())
        .arg("--out")
        .arg(input_file.path());
    cmd_input
        .assert()
        .failure()
        .stderr(predicate::str::contains("regenerate it with `smt key --xsk"));
}

// ------------------------------------------------------------------
// compute-inputs command tests
// ------------------------------------------------------------------

#[test]
fn compute_inputs_basic() {
    let transcript = NamedTempFile::new().unwrap();
    fs::write(transcript.path(), "1 100\n2 200\n3 300\n").unwrap();
    let out_file = NamedTempFile::new().unwrap();

    let mut cmd = Command::cargo_bin("smt").unwrap();
    cmd.arg("compute-inputs")
        .arg("--depth")
        .arg("2")
        .arg("--transcript")
        .arg(transcript.path())
        .arg("--nullifier")
        .arg("2")
        .arg("--out")
        .arg(out_file.path());

    cmd.assert()
        .success()
        .stderr(predicate::str::contains("Witness input written to"))
        .stderr(predicate::str::contains("digest:"))
        .stderr(predicate::str::contains("nullifier:"))
        .stderr(predicate::str::contains("nonce:"))
        .stderr(predicate::str::contains("siblings:"));

    // Verify JSON output
    let json_text = fs::read_to_string(out_file.path()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&json_text).unwrap();
    assert_eq!(json["nullifier"], "2");
    assert_eq!(json["nonce"], "200");
    assert!(json["digest"].as_str().unwrap().len() > 0);
    assert!(json["sibling[0]"].is_string());
    assert!(json["sibling[1]"].is_string());
    assert!(json["direction[0]"].is_string());
    assert!(json["direction[1]"].is_string());
}

#[test]
fn compute_inputs_nullifier_not_found() {
    let transcript = NamedTempFile::new().unwrap();
    fs::write(transcript.path(), "1 100\n2 200\n").unwrap();
    let out_file = NamedTempFile::new().unwrap();

    let mut cmd = Command::cargo_bin("smt").unwrap();
    cmd.arg("compute-inputs")
        .arg("--depth")
        .arg("2")
        .arg("--transcript")
        .arg(transcript.path())
        .arg("--nullifier")
        .arg("99")
        .arg("--out")
        .arg(out_file.path());

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Nullifier not found"));
}

#[test]
fn compute_inputs_with_raw_commitments() {
    let transcript = NamedTempFile::new().unwrap();
    fs::write(transcript.path(), "10\n20\n30\n").unwrap();
    let out_file = NamedTempFile::new().unwrap();

    let mut cmd = Command::cargo_bin("smt").unwrap();
    cmd.arg("compute-inputs")
        .arg("--depth")
        .arg("2")
        .arg("--transcript")
        .arg(transcript.path())
        .arg("--nullifier")
        .arg("10")
        .arg("--out")
        .arg(out_file.path());

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Nullifier not found"));
}

#[test]
fn compute_inputs_missing_transcript() {
    let out_file = NamedTempFile::new().unwrap();

    let mut cmd = Command::cargo_bin("smt").unwrap();
    cmd.arg("compute-inputs")
        .arg("--depth")
        .arg("2")
        .arg("--transcript")
        .arg("/nonexistent/transcript.txt")
        .arg("--nullifier")
        .arg("1")
        .arg("--out")
        .arg(out_file.path());

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("failed to read transcript"));
}

// ------------------------------------------------------------------
// --help output tests
// ------------------------------------------------------------------

/// Top-level `--help` prints the usage summary.
#[test]
fn help_top_level() {
    let mut cmd = Command::cargo_bin("smt").unwrap();
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Usage: smt <COMMAND>"))
        .stdout(predicate::str::contains("Commands:"))
        .stdout(predicate::str::contains("key"))
        .stdout(predicate::str::contains("leaf"))
        .stdout(predicate::str::contains("insert"))
        .stdout(predicate::str::contains("digest"))
        .stdout(predicate::str::contains("path"))
        .stdout(predicate::str::contains("verify"))
        .stdout(predicate::str::contains("export"))
        .stdout(predicate::str::contains("cardano-input"))
        .stdout(predicate::str::contains("compute-inputs"));
}

/// `insert --help` shows the --depth, --items, --transcript, and --state options.
#[test]
fn help_insert() {
    let mut cmd = Command::cargo_bin("smt").unwrap();
    cmd.arg("insert").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("--depth"))
        .stdout(predicate::str::contains("--items"))
        .stdout(predicate::str::contains("--transcript"))
        .stdout(predicate::str::contains("--state"))
        .stdout(predicate::str::contains("Merkle tree depth (number of levels)"))
        .stdout(predicate::str::contains("Comma-separated list of items to insert"));
}

/// `compute-inputs --help` shows the expected options.
#[test]
fn help_compute_inputs() {
    let mut cmd = Command::cargo_bin("smt").unwrap();
    cmd.arg("compute-inputs").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("--depth"))
        .stdout(predicate::str::contains("--transcript"))
        .stdout(predicate::str::contains("--nullifier"))
        .stdout(predicate::str::contains("--out"));
}
