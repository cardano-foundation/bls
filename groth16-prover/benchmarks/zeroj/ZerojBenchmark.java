package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;

import java.io.FileInputStream;
import java.math.BigInteger;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Standalone benchmark: zeroj Groth16 prover (BLS12-381) on real Circom circuits.
 *
 * <p>Run with:</p>
 * <pre>
 *   javac -cp "zeroj-crypto/build/classes/java/main:zeroj-api/build/classes/java/main:zeroj-bls12381/build/classes/java/main" \
 *         src/bench/java/com/bloxbean/cardano/zeroj/crypto/groth16/ZerojBenchmark.java
 *   java  -cp ".:zeroj-crypto/build/classes/java/main:zeroj-api/build/classes/java/main:zeroj-bls12381/build/classes/java/main" \
 *         com.bloxbean.cardano.zeroj.crypto.groth16.ZerojBenchmark
 * </pre>
 */
public class ZerojBenchmark {

    static final int WARMUP = 3;

    public static void main(String[] args) throws Exception {
        System.out.println("═══════════════════════════════════════════════════════════════════════");
        System.out.println("  Benchmark: zeroj Groth16 prover (BLS12-381) on Circom circuits");
        System.out.println("═══════════════════════════════════════════════════════════════════════");

        benchCircuit("PoseidonMerkle depth-2",
            "../groth16-prover/circom/PoseidonMerkle/poseidon_merkle_depth2.r1cs", 10);

        benchCircuit("EdDSAJubJub test_pbk_only",
            "../groth16-prover/circom/EdDSAJubJub/test_pbk_only.r1cs", 3);

        System.out.println("\n═══════════════════════════════════════════════════════════════════════");
        System.out.println("  zeroj benchmark complete.");
        System.out.println("═══════════════════════════════════════════════════════════════════════");
    }

    static void benchCircuit(String name, String r1csPath, int iterations) throws Exception {
        System.out.println("\n=== zeroj: " + name + " ===");

        Path path = Paths.get(r1csPath);
        var data = R1CSImporter.importR1CS(new FileInputStream(path.toFile()));

        System.out.println("  Wires:       " + data.numWires());
        System.out.println("  Constraints: " + data.numConstraints());
        System.out.println("  Public:      " + data.numPublic());

        int domainSize = Integer.highestOneBit(data.numConstraints() - 1) << 1;
        if (domainSize < 2) domainSize = 2;

        // Setup (ceremony)
        long setupStart = System.nanoTime();
        var srs = PowersOfTauBLS381.generate(domainSize);
        var setup = Groth16SetupBLS381.setup(data.constraints(), data.numWires(), data.numPublic(), srs.tauScalar());
        long setupNs = System.nanoTime() - setupStart;
        var pk = setup.provingKey();

        // Dummy witness (all ones — not necessarily valid for the circuit logic,
        // but sufficient for measuring prover throughput)
        BigInteger[] witness = new BigInteger[data.numWires()];
        for (int i = 0; i < witness.length; i++) witness[i] = BigInteger.ONE;
        witness[0] = BigInteger.ONE;

        // Warm-up
        for (int i = 0; i < WARMUP; i++) {
            Groth16ProverBLS381.prove(pk, witness, data.constraints(), data.numWires(), domainSize);
        }

        // Timed run
        long start = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            Groth16ProverBLS381.prove(pk, witness, data.constraints(), data.numWires(), domainSize);
        }
        long totalNs = System.nanoTime() - start;
        double perProofMs = totalNs / (iterations * 1_000_000.0);

        System.out.println("  Setup time:  " + String.format("%.2f", setupNs / 1_000_000_000.0) + " s");
        System.out.println("  Iterations:  " + iterations);
        System.out.println("  Total time:  " + String.format("%.2f", totalNs / 1_000_000_000.0) + " s");
        System.out.println("  Per-proof:   " + String.format("%.2f", perProofMs) + " ms");
        System.out.println("  (≈ " + String.format("%.2f", perProofMs / 1000.0) + " s per proof)");
    }
}
