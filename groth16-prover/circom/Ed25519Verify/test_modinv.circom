pragma circom 2.0.0;

include "modinv.circom";

template TestBigModInv51() {
  signal input in[3];
  signal output out[3];

  component inv = BigModInv51();
  for (var i = 0; i < 3; i++) {
    inv.in[i] <== in[i];
  }
  for (var i = 0; i < 3; i++) {
    out[i] <== inv.out[i];
  }
}

component main = TestBigModInv51();
