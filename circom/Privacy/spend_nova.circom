pragma circom 2.0.0;

// Privacy/Spend — Nova IVC step circuit (one MiMC Merkle level per step).
//
//   state_out = MiMC2(switch(state_in, sibling, direction))
//
// A chain of `depth` steps walks a leaf commitment (MiMC2(nullifier, nonce),
// hashed off-chain into the initial state) up to the tree root.  The public
// input is exactly the state (n_pub_in == n_pub_out == 1).

include "./spend.circom";

template SpendStep() {
    signal input state_in;
    signal input sibling;
    signal input direction;
    signal output state_out;

    component sw = SelectiveSwitch();
    sw.in0 <== state_in;
    sw.in1 <== sibling;
    sw.s   <== direction;

    component hasher = Mimc2();
    hasher.in0 <== sw.out0;
    hasher.in1 <== sw.out1;
    state_out <== hasher.out;
}

component main {public [state_in]} = SpendStep();
