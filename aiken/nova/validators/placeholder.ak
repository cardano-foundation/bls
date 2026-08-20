use nova/types.{FinalInstance, CircuitParams, SlimProof}
use nova/verifier

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
