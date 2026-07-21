package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import org.junit.jupiter.api.Test;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Benchmark: zeroj Groth16 prover (BLS12-381) on real Circom circuits.
 *
 * <p>Compares proving time for circuits loaded from standard .r1cs files
 * (PoseidonMerkle depth-2, EdDSAJubJub test_pbk_only) against the
 * numbers reported by the Rust groth16-prover crate.</p>
 */
class ZerojGroth16BenchmarkTest {

    static final int WARMUP_ITERATIONS = 3;

    @Test
    void benchmarkPoseidonMerkleDepth2() throws IOException {
        Path r1cs = Paths.get("../groth16-prover/circom/PoseidonMerkle/poseidon_merkle_depth2.r1cs");
        var data = R1CSImporter.importR1CS(new FileInputStream(r1cs.toFile()));

        System.out.println("\n=== zeroj: PoseidonMerkle depth-2 ===");
        System.out.println("  Wires:       " + data.numWires());
        System.out.println("  Constraints: " + data.numConstraints());
        System.out.println("  Public:      " + data.numPublic());

        int domainSize = Integer.highestOneBit(data.numConstraints() - 1) << 1;
        if (domainSize < 2) domainSize = 2;

        var srs = PowersOfTauBLS381.generate(domainSize);
        var setup = Groth16SetupBLS381.setup(data.constraints(), data.numWires(), data.numPublic(), srs.tauScalar());
        var pk = setup.provingKey();

        BigInteger[] witness = new BigInteger[data.numWires()];
        for (int i = 0; i < witness.length; i++) witness[i] = BigInteger.ONE;
        witness[0] = BigInteger.ONE; // constant wire

        // Warm-up
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            Groth16ProverBLS381.prove(pk, witness, data.constraints(), data.numWires(), domainSize);
        }

        int iterations = 10;
        long start = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            Groth16ProverBLS381.prove(pk, witness, data.constraints(), data.numWires(), domainSize);
        }
        long totalNs = System.nanoTime() - start;
        double perProofMs = totalNs / (iterations * 1_000_000.0);

        System.out.println("  Iterations:  " + iterations);
        System.out.println("  Total time:  " + (totalNs / 1_000_000_000.0) + " s");
        System.out.println("  Per-proof:   " + String.format("%.2f", perProofMs) + " ms");
        System.out.println("  (≈ " + String.format("%.2f", perProofMs / 1000.0) + " s per proof)");

        assertTrue(perProofMs > 0, "Benchmark produced a positive time");
    }

    @Test
    void benchmarkEdDSAJubJub() throws IOException {
        Path r1cs = Paths.get("../groth16-prover/circom/EdDSAJubJub/test_pbk_only.r1cs");
        var data = R1CSImporter.importR1CS(new FileInputStream(r1cs.toFile()));

        System.out.println("\n=== zeroj: EdDSAJubJub test_pbk_only ===");
        System.out.println("  Wires:       " + data.numWires());
        System.out.println("  Constraints: " + data.numConstraints());
        System.out.println("  Public:      " + data.numPublic());

        int domainSize = Integer.highestOneBit(data.numConstraints() - 1) << 1;
        if (domainSize < 2) domainSize = 2;

        var srs = PowersOfTauBLS381.generate(domainSize);
        var setup = Groth16SetupBLS381.setup(data.constraints(), data.numWires(), data.numPublic(), srs.tauScalar());
        var pk = setup.provingKey();

        BigInteger[] witness = new BigInteger[data.numWires()];
        for (int i = 0; i < witness.length; i++) witness[i] = BigInteger.ONE;
        witness[0] = BigInteger.ONE;

        // Warm-up
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            Groth16ProverBLS381.prove(pk, witness, data.constraints(), data.numWires(), domainSize);
        }

        int iterations = 3;
        long start = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            Groth16ProverBLS381.prove(pk, witness, data.constraints(), data.numWires(), domainSize);
        }
        long totalNs = System.nanoTime() - start;
        double perProofMs = totalNs / (iterations * 1_000_000.0);

        System.out.println("  Iterations:  " + iterations);
        System.out.println("  Total time:  " + (totalNs / 1_000_000_000.0) + " s");
        System.out.println("  Per-proof:   " + String.format("%.2f", perProofMs) + " ms");
        System.out.println("  (≈ " + String.format("%.2f", perProofMs / 1000.0) + " s per proof)");

        assertTrue(perProofMs > 0, "Benchmark produced a positive time");
    }
}
