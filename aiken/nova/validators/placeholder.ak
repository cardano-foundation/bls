use nova/types.{FinalInstance, CircuitParams, SlimProof}
use nova/verifier

/// Plutus V3 spending validator: verifies a Nova slim sumcheck proof.
/// The datum carries the expected circuit parameters; the redeemer is the proof.
validator nova_slim_verify {
  spend(datum: Option<CircuitParams>, redeemer: SlimProof, _self: Data, _tx: Data) -> Bool {
    expect Some(params) = datum
    redeemer.circuit_params == params
      && verifier.verify_slim(redeemer)
  }

  else(_) {
    fail
  }
}

test test_verify_single_round_valid() {
  let proof = SlimProof {
    circuit_params: CircuitParams {
      n_wires: 4,
      n_constraints: 2,
      n_pub_out: 1,
      n_pub_in: 1,
    },
    final_instance: FinalInstance {
      x: [0],
      u: 1,
      w_commit: #"",
      e_commit: #"",
    },
    sumcheck_polys: [[0, 0]],
    sumcheck_claims: [0, 0],
    r_challenges: [42],
    claimed_product_at_r: 0,
    w_commit_hash: #"",
    e_commit_hash: #"",
  }
  verifier.verify_slim(proof)
}

test test_verify_two_rounds_valid() {
  let proof = SlimProof {
    circuit_params: CircuitParams {
      n_wires: 8,
      n_constraints: 4,
      n_pub_out: 1,
      n_pub_in: 1,
    },
    final_instance: FinalInstance {
      x: [0],
      u: 1,
      w_commit: #"",
      e_commit: #"",
    },
    sumcheck_polys: [[0, 0], [0, 0]],
    sumcheck_claims: [0, 0, 0],
    r_challenges: [7, 13],
    claimed_product_at_r: 0,
    w_commit_hash: #"",
    e_commit_hash: #"",
  }
  verifier.verify_slim(proof)
}

test test_verify_nonzero_poly_valid() {
  let proof = SlimProof {
    circuit_params: CircuitParams {
      n_wires: 4,
      n_constraints: 2,
      n_pub_out: 1,
      n_pub_in: 1,
    },
    final_instance: FinalInstance {
      x: [0],
      u: 1,
      w_commit: #"",
      e_commit: #"",
    },
    sumcheck_polys: [[3, 7]],
    sumcheck_claims: [13, 24],
    r_challenges: [3],
    claimed_product_at_r: 24,
    w_commit_hash: #"",
    e_commit_hash: #"",
  }
  verifier.verify_slim(proof)
}

test test_verify_wrong_initial_sum() {
  let proof = SlimProof {
    circuit_params: CircuitParams {
      n_wires: 4,
      n_constraints: 2,
      n_pub_out: 1,
      n_pub_in: 1,
    },
    final_instance: FinalInstance {
      x: [0],
      u: 1,
      w_commit: #"",
      e_commit: #"",
    },
    sumcheck_polys: [[0, 0]],
    sumcheck_claims: [1, 0],
    r_challenges: [42],
    claimed_product_at_r: 0,
    w_commit_hash: #"",
    e_commit_hash: #"",
  }
  verifier.verify_slim(proof) == False
}

test test_verify_wrong_final_claim() {
  let proof = SlimProof {
    circuit_params: CircuitParams {
      n_wires: 4,
      n_constraints: 2,
      n_pub_out: 1,
      n_pub_in: 1,
    },
    final_instance: FinalInstance {
      x: [0],
      u: 1,
      w_commit: #"",
      e_commit: #"",
    },
    sumcheck_polys: [[0, 0]],
    sumcheck_claims: [0, 1],
    r_challenges: [42],
    claimed_product_at_r: 0,
    w_commit_hash: #"",
    e_commit_hash: #"",
  }
  verifier.verify_slim(proof) == False
}

test test_verify_mismatched_counts() {
  let proof = SlimProof {
    circuit_params: CircuitParams {
      n_wires: 4,
      n_constraints: 2,
      n_pub_out: 1,
      n_pub_in: 1,
    },
    final_instance: FinalInstance {
      x: [0],
      u: 1,
      w_commit: #"",
      e_commit: #"",
    },
    sumcheck_polys: [[0, 0]],
    sumcheck_claims: [0],
    r_challenges: [42],
    claimed_product_at_r: 0,
    w_commit_hash: #"",
    e_commit_hash: #"",
  }
  verifier.verify_slim(proof) == False
}

test test_cko_real_challenge_values() {
  let proof = SlimProof {
    circuit_params: CircuitParams {
      n_wires: 7658,
      n_constraints: 7724,
      n_pub_out: 24,
      n_pub_in: 24,
    },
    final_instance: FinalInstance {
      x: [
        0, 0, 0, 7927649477821046993507722220378443230165516303373512209787894650187722847620,
        0, 0, 7927649477821046993507722220378443230165516303373512209787894650187722847620, 0,
        0, 0, 0, 0,
        15422521118077880740007085776393643212260019298014476238410149773337512186146, 5595040906052288055355704578677759305761602444402666324778963121975385293178, 21909948341810160139381980532478186313934982236307923013022335372302122002038, 14449062279011259249051953921763456347914495118046350957374811890114158199896,
        17184988157455465111853733684261667077026818895506613134778294728844488755757, 37749392775709001311118317674951396971877437259726859383976314321709604453307, 7927649477821046993507722220378443230165516303373512209787894650187722847620, 0,
        0, 42843966911242945530579817777943228292521552851831537017017597892324392617563, 35527612378120604739438695755269130506998010819847906873541921830433140168995, 45200121865928831319248866211881409295712915184658479109716894766673902594290,
        0, 0, 0, 7927649477821046993507722220378443230165516303373512209787894650187722847620,
        0, 0, 7927649477821046993507722220378443230165516303373512209787894650187722847620, 0,
        0, 0, 0, 0,
        15422521118077880740007085776393643212260019298014476238410149773337512186146, 5595040906052288055355704578677759305761602444402666324778963121975385293178, 21909948341810160139381980532478186313934982236307923013022335372302122002038, 14449062279011259249051953921763456347914495118046350957374811890114158199896,
        17184988157455465111853733684261667077026818895506613134778294728844488755757, 37749392775709001311118317674951396971877437259726859383976314321709604453307, 7927649477821046993507722220378443230165516303373512209787894650187722847620, 0,
        0, 42843966911242945530579817777943228292521552851831537017017597892324392617563, 35527612378120604739438695755269130506998010819847906873541921830433140168995, 45200121865928831319248866211881409295712915184658479109716894766673902594290,
      ],
      u: 1,
      w_commit: #"",
      e_commit: #"",
    },
    sumcheck_polys: [[0, 0], [0, 0]],
    sumcheck_claims: [0, 0, 0],
    r_challenges: [21328464620381525131075982840458371645799272542070335445245641326034385905465, 35298660858522474984503527911410353411961069035692671428956584329070080986422],
    claimed_product_at_r: 0,
    w_commit_hash: #"",
    e_commit_hash: #"",
  }
  verifier.verify_slim(proof) == True
}

test test_tampered_cko_wrong_initial_sum() {
  let proof = SlimProof {
    circuit_params: CircuitParams {
      n_wires: 7658,
      n_constraints: 7724,
      n_pub_out: 24,
      n_pub_in: 24,
    },
    final_instance: FinalInstance {
      x: [0, 0, 0, 0],
      u: 1,
      w_commit: #"",
      e_commit: #"",
    },
    sumcheck_polys: [[0, 0], [0, 0], [0, 0]],
    sumcheck_claims: [1, 0, 0],
    r_challenges: [42, 43],
    claimed_product_at_r: 0,
    w_commit_hash: #"",
    e_commit_hash: #"",
  }
  verifier.verify_slim(proof) == False
}

