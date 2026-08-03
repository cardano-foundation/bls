pragma circom 2.0.0;

// Blake2b-224 pre-image — Nova IVC step circuit (one compression per step).
//
// The original `CompressionF(t, f)` takes t and f as compile-time constants.
// This step circuit needs them as runtime signals (the block index / final
// flag vary per step), so `CompressionFVar` replicates it with:
//   - t decomposed into two 64-bit words via ToBits(128)
//   - f ∈ {0,1} expanded to f_word = f * (2^64 - 1)
// and XOR-ed into the IV block with runtime XorWord3 instead of XorWordConst.
//
// State (public, 10 signals): h[8] (the 8 qwords of the running hash),
// t (byte counter), f (final flag).  t and f are passed through to the
// outputs so n_pub_in == n_pub_out == 10 and the CLI chain rule holds.
//
// A 32-byte Blake2b-224 pre-image uses a single 128-byte block: the CLI
// folds it as one step with t = 32, f = 1.

include "blake2b.circom";

// Compression function F with runtime t (byte counter, < 2^128) and f (final flag).
template CompressionFVar() {
  signal input  h[8];         // the state (8 qwords)
  signal input  m[16];        // the message block (16 qwords)
  signal input  t;            // byte offset counter
  signal input  f;            // 1 for the final block, 0 otherwise
  signal output out[8];       // new state

  component iv = IV();
  signal init[16];

  for(var i=0; i<8; i++) { init[i  ] <== h[i];      }
  for(var i=0; i<8; i++) { init[i+8] <== iv.out[i]; }

  // runtime t: t = t_lo + 2^64 * t_hi, both 64-bit words
  component tbits = ToBits(128);
  tbits.inp <== t;
  signal t_lo;
  signal t_hi;
  var lo = 0;
  var hi = 0;
  for(var i=0; i<64; i++) { lo += tbits.out[i]     * (1<<i); }
  for(var i=0; i<64; i++) { hi += tbits.out[i + 64] * (1<<i); }
  t_lo <== lo;
  t_hi <== hi;

  // runtime f: f_word = f * (2^64 - 1)
  signal f_word;
  f * (1 - f) === 0;
  f_word <== f * 0xFFFFFFFFFFFFFFFF;

  signal vs[13][16];

  component xor1 = XorWord3(64);
  component xor2 = XorWord3(64);
  component xor3 = XorWord3(64);

  for(var i=0; i<12; i++) { vs[0][i] <== init[i]; }
  xor1.x <== init[12]; xor1.y <== t_lo;   xor1.z <== 0;       xor1.out_word ==> vs[0][12];
  xor2.x <== init[13]; xor2.y <== t_hi;   xor2.z <== 0;       xor2.out_word ==> vs[0][13];
  xor3.x <== init[14]; xor3.y <== f_word; xor3.z <== 0;       xor3.out_word ==> vs[0][14];
  vs[0][15] <== init[15];

  component rounds[12];

  for(var i=0; i<12; i++) {
    rounds[i] = SingleRound(i);
    rounds[i].msg <== m;
    rounds[i].inp <== vs[i];
    rounds[i].out ==> vs[i+1];
  }

  component fin[8];
  for(var i=0; i<8; i++) {
    fin[i] = XorWord3(64);
    fin[i].x <== h[i];
    fin[i].y <== vs[12][i];
    fin[i].z <== vs[12][i+8];
    fin[i].out_word ==> out[i];
  }
}

// One Blake2b block compression as a Nova step: flat signals because the
// CLI's step-chain rule needs scalar public inputs/outputs.
template Blake2bBlockStep() {
  signal input h_in0;  signal input h_in1;  signal input h_in2;  signal input h_in3;
  signal input h_in4;  signal input h_in5;  signal input h_in6;  signal input h_in7;
  signal input m0;  signal input m1;  signal input m2;  signal input m3;
  signal input m4;  signal input m5;  signal input m6;  signal input m7;
  signal input m8;  signal input m9;  signal input m10; signal input m11;
  signal input m12; signal input m13; signal input m14; signal input m15;
  signal input t;
  signal input f;

  signal output h_out0;  signal output h_out1;  signal output h_out2;  signal output h_out3;
  signal output h_out4;  signal output h_out5;  signal output h_out6;  signal output h_out7;
  signal output t_out;
  signal output f_out;

  component c = CompressionFVar();
  c.h[0] <== h_in0;  c.h[1] <== h_in1;  c.h[2] <== h_in2;  c.h[3] <== h_in3;
  c.h[4] <== h_in4;  c.h[5] <== h_in5;  c.h[6] <== h_in6;  c.h[7] <== h_in7;
  c.m[0] <== m0;  c.m[1] <== m1;  c.m[2] <== m2;  c.m[3] <== m3;
  c.m[4] <== m4;  c.m[5] <== m5;  c.m[6] <== m6;  c.m[7] <== m7;
  c.m[8] <== m8;  c.m[9] <== m9;  c.m[10] <== m10; c.m[11] <== m11;
  c.m[12] <== m12; c.m[13] <== m13; c.m[14] <== m14; c.m[15] <== m15;
  c.t <== t;
  c.f <== f;

  h_out0 <== c.out[0];  h_out1 <== c.out[1];  h_out2 <== c.out[2];  h_out3 <== c.out[3];
  h_out4 <== c.out[4];  h_out5 <== c.out[5];  h_out6 <== c.out[6];  h_out7 <== c.out[7];
  t_out <== t;
  f_out <== f;
}

component main {public [h_in0, h_in1, h_in2, h_in3, h_in4, h_in5, h_in6, h_in7, t, f]} = Blake2bBlockStep();
