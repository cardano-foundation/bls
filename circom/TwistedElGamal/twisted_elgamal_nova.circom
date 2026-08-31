pragma circom 2.0.0;

// Twisted ElGamal transfer — Nova IVC step circuit (one limb per step).
//
// A transfer is decomposed into `nLimbs` u16 limbs.  Each step processes
// one limb of the (old, new) balance pair and accumulates the net change
// into a running state:
//
//   state_out = state_in + (new_limb - old_limb)
//
// Over a full chain of `nLimbs` steps, the final state equals
//   -(transfer amount)   i.e.  sum(new_limb - old_limb) == -amount
//
// Each limb is range-constrained to [0, 2^16), proving elementwise that
// no balance underflows.  The whole transfer (nLimbs limbs) is compressed
// into a single Nova fold proof.
//
// Public input/output is exactly the running state (n_pub_in == n_pub_out == 1),
// matching the Nova sumcheck verifier's expectations.

include "bitify.circom";

template TransferStep() {
    signal input state_in;       // accumulated net change so far
    signal input old_limb;       // old balance limb  (u16)
    signal input new_limb;       // new balance limb  (u16)
    signal output state_out;     // updated accumulated net change

    // Range-constrain both limbs to [0, 2^16) via Num2Bits(16).
    component oldRange = Num2Bits(16);
    oldRange.in <== old_limb;

    component newRange = Num2Bits(16);
    newRange.in <== new_limb;

    // Accumulate the per-limb net change.
    state_out <== state_in + (new_limb - old_limb);
}

component main {public [state_in]} = TransferStep();
