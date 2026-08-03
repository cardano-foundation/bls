pragma circom 2.0.0;

// Cardano Key Ownership (JubJub) — Nova IVC step circuit (one scalar-mul
// bit per step).
//
// Each step computes, in twisted-Edwards coordinates over BLS12-381:
//   acc_out = 2*acc_in + bit*BASE8
// where BASE8 = 8·G_JubJub is the fixed base point of the original
// `cardano_key_ownership.circom` circuit.  A chain of 254 steps computes
// acc = [sk]·BASE8 starting from the identity acc_0 = (0, 1).  The public
// key (pk_x, pk_y) is chained unchanged; the app checks acc == pk after
// the fold.
//
// State (public, 4 + 4 signals, flattened to scalars): acc and pk.
// n_pub_in == n_pub_out == 4.

include "jubjub_primitives.circom";

template CardanoKeyOwnershipStep() {
    signal input acc_x;
    signal input acc_y;
    signal input pk_x;
    signal input pk_y;
    signal input bit;

    signal output acc_out_x;
    signal output acc_out_y;
    signal output pk_out_x;
    signal output pk_out_y;

    var BASE8[2] = [
        28336281903124990867587793011069573392383982287722241916350956173377953689573,
        39385640392217313770878525135509063452020585410343666726093009378539878503883
    ];

    bit * (1 - bit) === 0;

    component dbl = JubJubDbl();
    dbl.x <== acc_x;
    dbl.y <== acc_y;

    component add = JubJubAdd();
    add.x1 <== dbl.xout;
    add.y1 <== dbl.yout;
    add.x2 <== BASE8[0];
    add.y2 <== BASE8[1];

    signal mux_x;
    signal mux_y;
    mux_x <== add.xout * bit;
    mux_y <== add.yout * bit;
    acc_out_x <== mux_x + dbl.xout - dbl.xout * bit;
    acc_out_y <== mux_y + dbl.yout - dbl.yout * bit;

    pk_out_x <== pk_x;
    pk_out_y <== pk_y;
}

component main {public [acc_x, acc_y, pk_x, pk_y]} = CardanoKeyOwnershipStep();
