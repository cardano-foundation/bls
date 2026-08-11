use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::NamedTempFile;

// ------------------------------------------------------------------
// Synthetic .r1cs generator (self-contained tests)
// ------------------------------------------------------------------

/// Generate a synthetic `.r1cs` file for the 3-gate multiplier circuit.
fn build_synthetic_r1cs() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"r1cs");
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&2u32.to_le_bytes());

    let field_size = 32u32;
    let n_wires = 8u32;
    let n_pub_out = 1u32;
    let n_pub_in = 0u32;
    let n_prv_in = 4u32;
    let n_labels = 8u64;
    let n_constraints = 3u32;

    let mut header = Vec::new();
    header.extend_from_slice(&field_size.to_le_bytes());
    header.extend_from_slice(&[0u8; 32]);
    header.extend_from_slice(&n_wires.to_le_bytes());
    header.extend_from_slice(&n_pub_out.to_le_bytes());
    header.extend_from_slice(&n_pub_in.to_le_bytes());
    header.extend_from_slice(&n_prv_in.to_le_bytes());
    header.extend_from_slice(&n_labels.to_le_bytes());
    header.extend_from_slice(&n_constraints.to_le_bytes());

    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&(header.len() as u64).to_le_bytes());
    out.extend_from_slice(&header);

    let mut constraints = Vec::new();
    let mut write_vec = |terms: &[(u32, u64)]| {
        constraints.extend_from_slice(&(terms.len() as u32).to_le_bytes());
        for &(w, v) in terms {
            constraints.extend_from_slice(&w.to_le_bytes());
            constraints.push(v as u8);
            constraints.extend_from_slice(&vec![0u8; field_size as usize - 1]);
        }
    };

    // x1*x2 = x5
    write_vec(&[(2, 1)]);
    write_vec(&[(3, 1)]);
    write_vec(&[(6, 1)]);
    // x3*x4 = x6
    write_vec(&[(4, 1)]);
    write_vec(&[(5, 1)]);
    write_vec(&[(7, 1)]);
    // x5*x6 = a
    write_vec(&[(6, 1)]);
    write_vec(&[(7, 1)]);
    write_vec(&[(1, 1)]);

    out.extend_from_slice(&2u32.to_le_bytes());
    out.extend_from_slice(&(constraints.len() as u64).to_le_bytes());
    out.extend_from_slice(&constraints);
    out
}

/// Generate a synthetic `.r1cs` for a 1-constraint step circuit with
/// `n_pub_out == n_pub_in == 1`: wires `[1, out, in, x]`, constraint `in·x = out`.
fn build_synthetic_step_r1cs() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"r1cs");
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&2u32.to_le_bytes());

    let field_size = 32u32;
    let n_wires = 4u32;
    let n_pub_out = 1u32;
    let n_pub_in = 1u32;
    let n_prv_in = 1u32;
    let n_labels = 4u64;
    let n_constraints = 1u32;

    let mut header = Vec::new();
    header.extend_from_slice(&field_size.to_le_bytes());
    header.extend_from_slice(&[0u8; 32]);
    header.extend_from_slice(&n_wires.to_le_bytes());
    header.extend_from_slice(&n_pub_out.to_le_bytes());
    header.extend_from_slice(&n_pub_in.to_le_bytes());
    header.extend_from_slice(&n_prv_in.to_le_bytes());
    header.extend_from_slice(&n_labels.to_le_bytes());
    header.extend_from_slice(&n_constraints.to_le_bytes());

    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&(header.len() as u64).to_le_bytes());
    out.extend_from_slice(&header);

    let mut constraints = Vec::new();
    let mut write_vec = |terms: &[(u32, u64)]| {
        constraints.extend_from_slice(&(terms.len() as u32).to_le_bytes());
        for &(w, v) in terms {
            constraints.extend_from_slice(&w.to_le_bytes());
            constraints.push(v as u8);
            constraints.extend_from_slice(&vec![0u8; field_size as usize - 1]);
        }
    };

    // in * x = out  (A = wire 2, B = wire 3, C = wire 1)
    write_vec(&[(2, 1)]);
    write_vec(&[(3, 1)]);
    write_vec(&[(1, 1)]);

    out.extend_from_slice(&2u32.to_le_bytes());
    out.extend_from_slice(&(constraints.len() as u64).to_le_bytes());
    out.extend_from_slice(&constraints);
    out
}

/// Serialize witness values to a valid Circom `.wtns` blob.  The values are
/// stored as canonical little-endian field elements (the values are small
/// u64s here, so the canonical form is 8 value bytes + 24 zero bytes), which
/// matches how `parse_wtns` reads them back via `from_le_bytes_mod_order`.
fn wtns_bytes(witness: &[u64]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"wtns");
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&2u32.to_le_bytes());

    let mut header = Vec::new();
    header.extend_from_slice(&32u32.to_le_bytes());
    header.extend_from_slice(&[0u8; 32]);
    header.extend_from_slice(&(witness.len() as u32).to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&(header.len() as u64).to_le_bytes());
    out.extend_from_slice(&header);

    let mut data = Vec::new();
    for v in witness {
        data.extend_from_slice(&v.to_le_bytes());
        data.extend_from_slice(&[0u8; 24]);
    }
    out.extend_from_slice(&2u32.to_le_bytes());
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    out.extend_from_slice(&data);
    out
}

/// Write one chained step witness for the synthetic step circuit:
/// `[1, out, in, x]` with `out = in·x`.  Returns `out` as the next state in.
fn write_step_wtns(dir: &std::path::Path, idx: usize, st_in: u64, x: u64) -> u64 {
    let st_out = st_in * x;
    fs::write(
        dir.join(format!("step_{idx:04}.wtns")),
        wtns_bytes(&[1, st_out, st_in, x]),
    )
    .unwrap();
    st_out
}

// ------------------------------------------------------------------
// Nova / Implementation 8 — CardanoKeyOwnership step-chain tests
//
// Implementation 8 splits the monolithic Ed25519 key-ownership proof into a
// chain of `BitElementMulAny` steps (one scalar-mul bit per step).  The step
// circuit `cardano_ed25519_ownership_nova.circom` has `n_pub_in == n_pub_out
// == 24` (the IVC state = (dblIn[4][3], addIn[4][3])), which `nova` enforces.
//
// The monolithic circuits (`cardano_ed25519_ownership.r1cs`,
// `cardano_key_ownership.r1cs`) must be *rejected* by `nova params` because
// their public-input width does not equal their public-output width.  The
// step-circuit tests (compile the .circom with
// `circom --prime bls12381 --r1cs --wasm`) skip when the compiled artifacts
// are not present.
// ------------------------------------------------------------------

fn cardano_key_ownership_dir() -> std::path::PathBuf {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("circom/CardanoKeyOwnership")
}

/// True if the user compiled the Nova step circuit (r1cs + wasm).
fn nova_step_artifacts_present() -> bool {
    let dir = cardano_key_ownership_dir();
    dir.join("cardano_ed25519_ownership_nova.r1cs").exists()
        && dir
            .join("cardano_ed25519_ownership_nova_js/cardano_ed25519_ownership_nova.wasm")
            .exists()
}

fn snarkjs_available() -> bool {
    std::process::Command::new("snarkjs")
        .arg("--version")
        .output()
        .is_ok()
}

/// Curve25519 base point G in extended coordinates, base-2^85 limbs
/// (from `cardano_ed25519_ownership.circom`).
const ED25519_BASE_POINT_G: [[&str; 3]; 4] = [
    [
        "6836562328990639286768922",
        "21231440843933962135602345",
        "10097852978535018773096760",
    ],
    [
        "7737125245533626718119512",
        "23211375736600880154358579",
        "30948500982134506872478105",
    ],
    ["1", "0", "0"],
    [
        "20943500354259764865654179",
        "24722277920680796426601402",
        "31289658119428895172835987",
    ],
];

/// Edwards identity in extended coordinates (X=0, Y=1, Z=1, T=0).
const EDWARDS_IDENTITY: [[&str; 3]; 4] = [
    ["0", "0", "0"],
    ["1", "0", "0"],
    ["1", "0", "0"],
    ["0", "0", "0"],
];

/// Build one step's input JSON from the current (dblIn, addIn) state.
fn step_input_json(dbl: &[[String; 3]; 4], add: &[[String; 3]; 4], sel: &str) -> String {
    let mut fields = serde_json::Map::new();
    for (i, row) in dbl.iter().enumerate() {
        for (j, v) in row.iter().enumerate() {
            fields.insert(
                format!("dbl_in_{i}_{j}"),
                serde_json::Value::String(v.clone()),
            );
        }
    }
    for (i, row) in add.iter().enumerate() {
        for (j, v) in row.iter().enumerate() {
            fields.insert(
                format!("add_in_{i}_{j}"),
                serde_json::Value::String(v.clone()),
            );
        }
    }
    fields.insert("sel".into(), serde_json::Value::String(sel.into()));
    serde_json::Value::Object(fields).to_string()
}

/// Extract a [4][3] block (12 values) starting at witness index `base`.
fn extract_witness_state(w: &[serde_json::Value], base: usize) -> [[String; 3]; 4] {
    std::array::from_fn(|i| {
        std::array::from_fn(|j| w[base + 3 * i + j].as_str().unwrap().to_string())
    })
}

/// Generate `count` chained step witnesses with snarkjs into `dir`.
///
/// The state starts at (dblIn = G, addIn = identity) and each step's public
/// outputs (witness indices 1..25) feed the next step's public inputs, so the
/// `state_in[i+1] == state_out[i]` chain invariant holds by construction.
fn generate_nova_step_witnesses(
    dir: &std::path::Path,
    wasm: &std::path::Path,
    count: usize,
) -> Result<(), String> {
    let mut dbl = ED25519_BASE_POINT_G.map(|r| r.map(String::from));
    let mut add = EDWARDS_IDENTITY.map(|r| r.map(String::from));

    for i in 0..count {
        let input_path = dir.join(format!("input_{i}.json"));
        let wtns_path = dir.join(format!("step_{i:04}.wtns"));
        let json_path = dir.join(format!("step_{i:04}.json"));

        fs::write(&input_path, step_input_json(&dbl, &add, "1"))
            .map_err(|e| format!("failed to write {}: {e}", input_path.display()))?;

        let status = std::process::Command::new("snarkjs")
            .arg("wtns")
            .arg("calculate")
            .arg(wasm)
            .arg(&input_path)
            .arg(&wtns_path)
            .status()
            .map_err(|e| format!("snarkjs failed to start: {e}"))?;
        if !status.success() {
            return Err(format!(
                "snarkjs wtns calculate failed for step {i} ({} != 0)",
                status.code().unwrap_or(-1)
            ));
        }

        let status = std::process::Command::new("snarkjs")
            .arg("wtns")
            .arg("export")
            .arg("json")
            .arg(&wtns_path)
            .arg(&json_path)
            .status()
            .map_err(|e| format!("snarkjs failed to start: {e}"))?;
        if !status.success() {
            return Err(format!(
                "snarkjs wtns export json failed for step {i} ({} != 0)",
                status.code().unwrap_or(-1)
            ));
        }

        let w: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&json_path).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        let w = w.as_array().ok_or("witness JSON is not an array")?;
        if w.len() < 25 {
            return Err(format!(
                "witness JSON has {} elements, expected >= 25",
                w.len()
            ));
        }
        // Public outputs (24) live at indices 1..25: [dblOut, addOut].
        dbl = extract_witness_state(w, 1);
        add = extract_witness_state(w, 13);
    }
    Ok(())
}

/// `nova params` must reject the monolithic Ed25519 ownership circuit:
/// its 256-bit public input `A` is not an IVC state.
#[test]
fn params_rejects_monolithic_ed25519_ownership() {
    let circuit = cardano_key_ownership_dir().join("cardano_ed25519_ownership.r1cs");
    assert!(
        circuit.exists(),
        "missing committed fixture {}",
        circuit.display()
    );

    let mut cmd = Command::cargo_bin("nova").unwrap();
    cmd.arg("params").arg("--circuit").arg(&circuit);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("not a valid step circuit"))
        .stderr(predicate::str::contains("n_pub_in (256) != n_pub_out (1)"));
}

/// Same invariant for the JubJub ownership circuit (public in = 2, public out = 0).
#[test]
fn params_rejects_jubjub_ownership() {
    let circuit = cardano_key_ownership_dir().join("cardano_key_ownership.r1cs");
    assert!(
        circuit.exists(),
        "missing committed fixture {}",
        circuit.display()
    );

    let mut cmd = Command::cargo_bin("nova").unwrap();
    cmd.arg("params").arg("--circuit").arg(&circuit);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("not a valid step circuit"))
        .stderr(predicate::str::contains("n_pub_in (2) != n_pub_out (0)"));
}

/// The synthetic multiplier circuit (1 pub out, 0 pub in) is not a step circuit.
#[test]
fn params_rejects_non_step_circuit() {
    let r1cs = NamedTempFile::new().unwrap();
    fs::write(r1cs.path(), build_synthetic_r1cs()).unwrap();

    let mut cmd = Command::cargo_bin("nova").unwrap();
    cmd.arg("params")
        .arg("--circuit")
        .arg(r1cs.path());

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("not a valid step circuit"))
        .stderr(predicate::str::contains("n_pub_in (0) != n_pub_out (1)"));
}

#[test]
fn params_missing_circuit() {
    let mut cmd = Command::cargo_bin("nova").unwrap();
    cmd.arg("params")
        .arg("--circuit")
        .arg("/tmp/does-not-exist-nova.r1cs");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("failed to load circuit"));
}

#[test]
fn params_invalid_circuit() {
    let bad_r1cs = NamedTempFile::new().unwrap();
    fs::write(bad_r1cs.path(), b"not_a_valid_r1cs_file").unwrap();

    let mut cmd = Command::cargo_bin("nova").unwrap();
    cmd.arg("params")
        .arg("--circuit")
        .arg(bad_r1cs.path());

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("failed to load circuit"));
}

/// `nova params` on the compiled step circuit reports the IVC state shape:
/// 24 public inputs = 24 public outputs, 1 private `sel` bit.
#[test]
fn params_accepts_cardano_ed25519_ownership_step() {
    if !nova_step_artifacts_present() {
        eprintln!("Nova step circuit artifacts missing; skipping params test");
        return;
    }

    let circuit = cardano_key_ownership_dir().join("cardano_ed25519_ownership_nova.r1cs");

    let mut cmd = Command::cargo_bin("nova").unwrap();
    cmd.arg("params").arg("--circuit").arg(&circuit);

    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "nova params failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let desc: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(desc["n_pub_out"], 24);
    assert_eq!(desc["n_pub_in"], 24);
    assert_eq!(desc["n_prv_in"], 1);
    assert!(desc["n_constraints"].as_u64().unwrap() > 0);
}

/// Run `nova ceremony` + `nova fold` over a chained witness directory and
/// return the (pk, vk, ivc) temp files.
fn nova_ceremony_and_fold(
    circuit: &std::path::Path,
    steps_dir: &std::path::Path,
) -> (NamedTempFile, NamedTempFile, NamedTempFile) {
    let pk = NamedTempFile::new().unwrap();
    let vk = NamedTempFile::new().unwrap();

    let mut ceremony = Command::cargo_bin("nova").unwrap();
    ceremony
        .arg("ceremony")
        .arg("--circuit")
        .arg(circuit)
        .arg("--proving-key")
        .arg(pk.path())
        .arg("--verifying-key")
        .arg(vk.path());
    ceremony.assert().success();

    let ivc = NamedTempFile::new().unwrap();
    let mut fold = Command::cargo_bin("nova").unwrap();
    fold.arg("fold")
        .arg("--circuit")
        .arg(circuit)
        .arg("--proving-key")
        .arg(pk.path())
        .arg("--steps")
        .arg(steps_dir)
        .arg("--out")
        .arg(ivc.path());
    fold.assert().success();

    (pk, vk, ivc)
}

/// Full Implementation 8 flow on CardanoKeyOwnership:
/// ceremony → fold → verify over a 3-step Ed25519 scalar-mul chain.
#[test]
fn cardano_ed25519_ownership_nova_fold_verify_e2e() {
    if !nova_step_artifacts_present() {
        eprintln!("Nova step circuit artifacts missing; skipping e2e test");
        return;
    }
    if !snarkjs_available() {
        eprintln!("snarkjs not installed; skipping e2e test");
        return;
    }

    let circuit = cardano_key_ownership_dir().join("cardano_ed25519_ownership_nova.r1cs");
    let wasm = cardano_key_ownership_dir()
        .join("cardano_ed25519_ownership_nova_js/cardano_ed25519_ownership_nova.wasm");

    let steps_dir = tempfile::tempdir().unwrap();
    generate_nova_step_witnesses(steps_dir.path(), &wasm, 3).unwrap();

    let (_pk, vk, ivc) = nova_ceremony_and_fold(&circuit, steps_dir.path());

    let mut verify = Command::cargo_bin("nova").unwrap();
    verify
        .arg("verify")
        .arg("--ivc")
        .arg(ivc.path())
        .arg("--verifying-key")
        .arg(vk.path());
    verify
        .assert()
        .success()
        .stderr(predicate::str::contains("Verified 3 steps"));
}

/// `nova fold` isolates the exact step whose `state_in` breaks the chain:
/// step 1 must be reported when step_0001.wtns does not follow step_0000.wtns.
#[test]
fn cardano_ed25519_ownership_nova_fold_rejects_broken_chain() {
    if !nova_step_artifacts_present() {
        eprintln!("Nova step circuit artifacts missing; skipping broken-chain test");
        return;
    }
    if !snarkjs_available() {
        eprintln!("snarkjs not installed; skipping broken-chain test");
        return;
    }

    let circuit = cardano_key_ownership_dir().join("cardano_ed25519_ownership_nova.r1cs");
    let wasm = cardano_key_ownership_dir()
        .join("cardano_ed25519_ownership_nova_js/cardano_ed25519_ownership_nova.wasm");

    // Generate 3 consecutive witnesses, then drop step 1 from the chain.
    let full_dir = tempfile::tempdir().unwrap();
    generate_nova_step_witnesses(full_dir.path(), &wasm, 3).unwrap();

    let broken_dir = tempfile::tempdir().unwrap();
    fs::copy(
        full_dir.path().join("step_0000.wtns"),
        broken_dir.path().join("step_0000.wtns"),
    )
    .unwrap();
    fs::copy(
        full_dir.path().join("step_0002.wtns"),
        broken_dir.path().join("step_0001.wtns"),
    )
    .unwrap();

    let (_pk, _vk, _ivc) = {
        let pk = NamedTempFile::new().unwrap();
        let vk = NamedTempFile::new().unwrap();
        let mut ceremony = Command::cargo_bin("nova").unwrap();
        ceremony
            .arg("ceremony")
            .arg("--circuit")
            .arg(&circuit)
            .arg("--proving-key")
            .arg(pk.path())
            .arg("--verifying-key")
            .arg(vk.path());
        ceremony.assert().success();

        let ivc = NamedTempFile::new().unwrap();
        let mut fold = Command::cargo_bin("nova").unwrap();
        fold.arg("fold")
            .arg("--circuit")
            .arg(&circuit)
            .arg("--proving-key")
            .arg(pk.path())
            .arg("--steps")
            .arg(broken_dir.path())
            .arg("--out")
            .arg(ivc.path());
        fold.assert()
            .failure()
            .stderr(predicate::str::contains(
                "state_in does not chain to previous state_out",
            ))
            .stderr(predicate::str::contains("step_0001.wtns"));
        (pk, vk, ivc)
    };
}

/// Tampering with any part of the IVC bundle is detected at verify time:
/// a modified final transcript fails the deterministic BLAKE2b512 re-derivation.
#[test]
fn cardano_ed25519_ownership_nova_verify_rejects_tampered_bundle() {
    if !nova_step_artifacts_present() {
        eprintln!("Nova step circuit artifacts missing; skipping tamper test");
        return;
    }
    if !snarkjs_available() {
        eprintln!("snarkjs not installed; skipping tamper test");
        return;
    }

    let circuit = cardano_key_ownership_dir().join("cardano_ed25519_ownership_nova.r1cs");
    let wasm = cardano_key_ownership_dir()
        .join("cardano_ed25519_ownership_nova_js/cardano_ed25519_ownership_nova.wasm");

    let steps_dir = tempfile::tempdir().unwrap();
    generate_nova_step_witnesses(steps_dir.path(), &wasm, 3).unwrap();

    let (_pk, vk, ivc) = nova_ceremony_and_fold(&circuit, steps_dir.path());

    // Corrupt the final transcript digest in the bundle.
    let mut bundle: serde_json::Value =
        serde_json::from_slice(&fs::read(ivc.path()).unwrap()).unwrap();
    bundle["transcript_final"] = serde_json::Value::String("0".repeat(128));
    fs::write(ivc.path(), serde_json::to_vec_pretty(&bundle).unwrap()).unwrap();

    let mut verify = Command::cargo_bin("nova").unwrap();
    verify
        .arg("verify")
        .arg("--ivc")
        .arg(ivc.path())
        .arg("--verifying-key")
        .arg(vk.path());
    verify
        .assert()
        .failure()
        .stderr(predicate::str::contains("final transcript mismatch"));
}

// ------------------------------------------------------------------
// Help output
// ------------------------------------------------------------------

/// `nova --help` lists all subcommands.
#[test]
fn help_top_level() {
    let mut cmd = Command::cargo_bin("nova").unwrap();
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Usage: nova <COMMAND>"))
        .stdout(predicate::str::contains("Commands:"))
        .stdout(predicate::str::contains("params"))
        .stdout(predicate::str::contains("ceremony"))
        .stdout(predicate::str::contains("fold"))
        .stdout(predicate::str::contains("verify"));
}

/// `nova ceremony --help` shows the --h-scalar option.
#[test]
fn help_ceremony() {
    let mut cmd = Command::cargo_bin("nova").unwrap();
    cmd.arg("ceremony").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("--h-scalar"))
        .stdout(predicate::str::contains("h-query scalar compression"))
        .stdout(predicate::str::contains("Use h-query scalar compression (Implementation 7)"));
}

// ------------------------------------------------------------------
// Error cases
// ------------------------------------------------------------------

/// `nova ceremony` fails when the circuit file does not exist.
#[test]
fn ceremony_missing_circuit() {
    let pk = NamedTempFile::new().unwrap();
    let vk = NamedTempFile::new().unwrap();

    let mut cmd = Command::cargo_bin("nova").unwrap();
    cmd.arg("ceremony")
        .arg("--circuit")
        .arg("/nonexistent/step_circuit.r1cs")
        .arg("--proving-key")
        .arg(pk.path())
        .arg("--verifying-key")
        .arg(vk.path());
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("failed to load circuit"));
}

/// `nova fold` fails early when the circuit is not a valid step circuit
/// (n_pub_in != n_pub_out), before even trying to load the proving key.
#[test]
fn fold_rejects_non_step_circuit() {
    let r1cs = NamedTempFile::new().unwrap();
    fs::write(r1cs.path(), build_synthetic_r1cs()).unwrap();
    let steps_dir = tempfile::tempdir().unwrap();
    let ivc = NamedTempFile::new().unwrap();

    let mut cmd = Command::cargo_bin("nova").unwrap();
    cmd.arg("fold")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--proving-key")
        .arg("/nonexistent/step.pk")
        .arg("--steps")
        .arg(steps_dir.path())
        .arg("--out")
        .arg(ivc.path());
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("not a valid step circuit"));
}

/// `nova verify` fails when the IVC bundle file does not exist.
#[test]
fn verify_missing_ivc() {
    let vk = NamedTempFile::new().unwrap();

    let mut cmd = Command::cargo_bin("nova").unwrap();
    cmd.arg("verify")
        .arg("--ivc")
        .arg("/nonexistent/bundle.ivc.json")
        .arg("--verifying-key")
        .arg(vk.path());
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("failed to read IVC bundle"));
}

// ------------------------------------------------------------------
// Nova / Implementation 9 — NIFS folding (constant-size bundle)
// ------------------------------------------------------------------

/// Full `nova fold --nifs` flow on a synthetic step circuit: folding is
/// transparent (no proving key), producing an O(1) NIFS bundle with a folded
/// Relaxed-R1CS final instance and a deterministic transcript.
#[test]
fn fold_nifs_end_to_end() {
    let r1cs = NamedTempFile::new().unwrap();
    fs::write(r1cs.path(), build_synthetic_step_r1cs()).unwrap();

    // State chain: 2 -> 6 -> 30 -> 210 (private factors 3, 5, 7).
    let steps_dir = tempfile::tempdir().unwrap();
    let mut state = 2u64;
    for (i, x) in [3u64, 5, 7].iter().enumerate() {
        state = write_step_wtns(steps_dir.path(), i, state, *x);
    }
    assert_eq!(state, 210);

    let bundle_file = NamedTempFile::new().unwrap();
    let mut cmd = Command::cargo_bin("nova").unwrap();
    cmd.arg("fold")
        .arg("--nifs")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--steps")
        .arg(steps_dir.path())
        .arg("--out")
        .arg(bundle_file.path());
    cmd.assert().success();

    let bundle: serde_json::Value =
        serde_json::from_slice(&fs::read(bundle_file.path()).unwrap()).unwrap();
    assert!(bundle.get("steps").is_none());
    assert!(bundle["final_instance"].is_object());
    assert_eq!(bundle["n_steps"], 3);
    assert_eq!(bundle["initial_state"], serde_json::json!(["2"]));
    // The final instance holds the *folded* accumulated state
    // (x_acc = x_0 + Σ r_i·x_i), not the last step's state — so just check
    // the structure and that folding is deterministic.
    assert_eq!(bundle["final_instance"]["x"].as_array().unwrap().len(), 2);
    assert_ne!(bundle["final_instance"]["u"].as_str().unwrap(), "1");
    assert!(
        bundle["final_instance"]["w_commit"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
    assert!(
        bundle["final_instance"]["e_commit"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
    assert_eq!(bundle["transcript_final"].as_str().unwrap().len(), 128);

    // Folding is deterministic: re-folding the same witnesses yields the
    // exact same bundle (challenges are transcript-derived, not sampled).
    let rerun = NamedTempFile::new().unwrap();
    let mut cmd = Command::cargo_bin("nova").unwrap();
    cmd.arg("fold")
        .arg("--nifs")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--steps")
        .arg(steps_dir.path())
        .arg("--out")
        .arg(rerun.path());
    cmd.assert().success();
    let bundle2: serde_json::Value =
        serde_json::from_slice(&fs::read(rerun.path()).unwrap()).unwrap();
    assert_eq!(bundle, bundle2);
}

/// `fold --nifs` isolates the exact step whose `state_in` breaks the chain.
#[test]
fn fold_nifs_rejects_broken_chain() {
    let r1cs = NamedTempFile::new().unwrap();
    fs::write(r1cs.path(), build_synthetic_step_r1cs()).unwrap();

    let full = tempfile::tempdir().unwrap();
    let mut state = 2u64;
    for (i, x) in [3u64, 5, 7].iter().enumerate() {
        state = write_step_wtns(full.path(), i, state, *x);
    }

    let broken = tempfile::tempdir().unwrap();
    fs::copy(
        full.path().join("step_0000.wtns"),
        broken.path().join("step_0000.wtns"),
    )
    .unwrap();
    fs::copy(
        full.path().join("step_0002.wtns"),
        broken.path().join("step_0001.wtns"),
    )
    .unwrap();

    let bundle_file = NamedTempFile::new().unwrap();
    let mut cmd = Command::cargo_bin("nova").unwrap();
    cmd.arg("fold")
        .arg("--nifs")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--steps")
        .arg(broken.path())
        .arg("--out")
        .arg(bundle_file.path());
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains(
            "state_in does not chain to previous state_out",
        ))
        .stderr(predicate::str::contains("step_0001.wtns"));
}

/// Without `--nifs`, `fold` still requires a proving key (clap).
#[test]
fn fold_requires_proving_key_without_nifs() {
    let r1cs = NamedTempFile::new().unwrap();
    fs::write(r1cs.path(), build_synthetic_step_r1cs()).unwrap();
    let steps_dir = tempfile::tempdir().unwrap();
    let out = NamedTempFile::new().unwrap();

    let mut cmd = Command::cargo_bin("nova").unwrap();
    cmd.arg("fold")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--steps")
        .arg(steps_dir.path())
        .arg("--out")
        .arg(out.path());
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains(
            "the following required arguments were not provided",
        ))
        .stderr(predicate::str::contains("--proving-key"));
}

/// `nova verify` on a NIFS bundle reports that the compression proof is
/// pending (Implementation 9 work item 2) instead of misreading the bundle.
#[test]
fn verify_nifs_bundle_reports_pending_compression() {
    let r1cs = NamedTempFile::new().unwrap();
    fs::write(r1cs.path(), build_synthetic_step_r1cs()).unwrap();

    let steps_dir = tempfile::tempdir().unwrap();
    let mut state = 2u64;
    for (i, x) in [3u64, 5, 7].iter().enumerate() {
        state = write_step_wtns(steps_dir.path(), i, state, *x);
    }

    let bundle_file = NamedTempFile::new().unwrap();
    let mut fold = Command::cargo_bin("nova").unwrap();
    fold.arg("fold")
        .arg("--nifs")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--steps")
        .arg(steps_dir.path())
        .arg("--out")
        .arg(bundle_file.path());
    fold.assert().success();

    let mut verify = Command::cargo_bin("nova").unwrap();
    verify
        .arg("verify")
        .arg("--ivc")
        .arg(bundle_file.path())
        .arg("--verifying-key")
        .arg("/nonexistent/step.vk");
    verify
        .assert()
        .failure()
        .stderr(predicate::str::contains("compression proof"));
}

/// `fold --nifs --compression-r1cs` emits the compression circuit `.r1cs`
/// (work item 2): 2× the step constraints, with only the `t_i` intermediates
/// private.  The output must parse back through the standard circuit loader so
/// it can be fed to `trusted-setup ceremony-dev --sparse`.
#[test]
fn fold_nifs_emits_compression_r1cs() {
    let r1cs = NamedTempFile::new().unwrap();
    fs::write(r1cs.path(), build_synthetic_step_r1cs()).unwrap();

    let steps_dir = tempfile::tempdir().unwrap();
    let mut state = 2u64;
    for (i, x) in [3u64, 5, 7].iter().enumerate() {
        state = write_step_wtns(steps_dir.path(), i, state, *x);
    }

    let bundle_file = NamedTempFile::new().unwrap();
    let compression_r1cs = tempfile::NamedTempFile::new().unwrap();
    let mut cmd = Command::cargo_bin("nova").unwrap();
    cmd.arg("fold")
        .arg("--nifs")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--steps")
        .arg(steps_dir.path())
        .arg("--out")
        .arg(bundle_file.path())
        .arg("--compression-r1cs")
        .arg(compression_r1cs.path());
    cmd.assert()
        .success()
        .stderr(predicate::str::contains("Compression circuit"));

    // Step circuit: 4 wires, 1 constraint, 1 public out + 1 public in.
    // Compression circuit: 2 constraints, n_public = 1+4+1+1 = 7,
    // n_wires_total = 8, n_pub_out = 6, n_prv_in = 1.
    let c = nova_prover::load_circuit(compression_r1cs.path()).expect("compression .r1cs must parse");
    assert_eq!(c.n_wires, 8);
    assert_eq!(c.n_constraints, 2);
    assert_eq!(c.n_pub_out, 6);
    assert_eq!(c.n_pub_in, 0);
    assert_eq!(c.n_prv_in, 1);

    // The bundle is still written regardless of the optional r1cs output.
    assert!(bundle_file.path().exists());
}
