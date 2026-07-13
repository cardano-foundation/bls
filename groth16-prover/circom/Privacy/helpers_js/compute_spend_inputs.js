const { mimc2 } = require("./mimc.js");
const { SparseMerkleTree } = require("./sparse_merkle_tree.js");
const fs = require("fs");

/*
 * Computes inputs to the Spend circuit.
 *
 * Inputs:
 *   depth: the depth of the merkle tree being used.
 *   transcript: A list of all commitments added to the tree.
 *               Each item is an array.
 *               If the array has one element, then that element is the commitment.
 *               Otherwise the array will have two elements, which are, in order:
 *                 the nullifier and the nonce.
 *   nullifier: The nullifier to print inputs to validity verifier for.
 *              This nullifier will be one of the nullifiers in the transcript.
 *
 * Return:
 *   an object of the form:
 * {
 *   "digest"            : ...,
 *   "nullifier"         : ...,
 *   "nonce"             : ...,
 *   "sibling[0]"        : ...,
 *   ...
 *   "direction[depth-1]": ...,
 * }
 */
function computeInput(depth, transcript, nullifier) {
    const tree = new SparseMerkleTree(depth);
    let targetNonce = null;

    for (const line of transcript) {
        if (line.length === 1) {
            tree.insert(line[0]);
        } else if (line.length === 2) {
            const [nf, nonce] = line;
            const commitment = mimc2(nf, nonce);
            tree.insert(commitment);
            if (nf.toString() === nullifier.toString()) {
                targetNonce = nonce.toString();
            }
        }
    }

    if (targetNonce === null) {
        throw new Error("Nullifier not found in transcript");
    }

    const commitment = mimc2(nullifier, targetNonce);
    const path = tree.path(commitment);

    const result = {
        digest: tree.digest,
        nullifier: nullifier.toString(),
        nonce: targetNonce,
    };

    for (let i = 0; i < depth; i++) {
        result[`sibling[${i}]`] = path[i][0];
        result[`direction[${i}]`] = path[i][1] ? "1" : "0";
    }

    return result;
}

module.exports = { computeInput };

// CLI usage
if (require.main === module) {
    const args = process.argv.slice(2);
    if (args.length < 3 || args.includes("-h") || args.includes("--help")) {
        console.log(`Usage: node helpers_js/compute_spend_inputs.js <depth> <transcript-file> <nullifier> [output-file]`);
        console.log(`  output-file defaults to input.json`);
        process.exit(1);
    }

    const depth = parseInt(args[0]);
    const transcriptFile = args[1];
    const nullifier = args[2];
    const outputFile = args[3] || "input.json";

    const transcript =
        fs.readFileSync(transcriptFile, { encoding: 'utf8' })
        .split(/\r?\n/)
        .filter(l => l.length > 0)
        .map(l => l.split(/\s+/));

    const input = computeInput(depth, transcript, nullifier);
    fs.writeFileSync(outputFile, JSON.stringify(input, null, 2) + "\n");
    console.log(`Wrote witness input to ${outputFile}`);
}
