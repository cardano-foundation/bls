pragma circom 2.0.0;

include "pointcompress.circom";

// Test PointCompress with the identity point (all zeros)
// Extended coordinates: [X, Y, Z, T] = [0, 1, 1, 0] in chunked 85-bit form
template TestPointCompress() {
  signal input P[4][3];
  signal output out[256];

  component comp = PointCompress();
  for (var i = 0; i < 4; i++) {
    for (var j = 0; j < 3; j++) {
      comp.P[i][j] <== P[i][j];
    }
  }
  for (var i = 0; i < 256; i++) {
    out[i] <== comp.out[i];
  }
}

component main = TestPointCompress();
