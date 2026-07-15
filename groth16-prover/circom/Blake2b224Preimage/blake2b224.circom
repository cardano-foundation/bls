pragma circom 2.0.0;

// Blake2b-224 hashing circuit
// Derived from bkomuves/hash-circuits (MIT License)
// Key change: nn = 28 (Blake2b-224) instead of nn = 32 (Blake2b-256).

include "blake2b.circom";

//------------------------------------------------------------------------------
// hash a sequence of `ll` bytes (Blake2b-224 — nn = 28)

template Blake2b224_bytes(ll) {
  signal input  inp_bytes[ll];
  signal output hash_words[4];    // ceil(28/8) = 4 qwords needed for output
  signal output hash_bytes[28];
  signal output hash_bits[256];   // 4 qwords * 64 bits = 256 bits computed

  var kk = 0;                   // key size in bytes
  var nn = 28;                  // final hash size in bytes (Blake2b-224)
  var dd = (ll + 127) \ 128;    // number of message blocks

  signal blocks[dd][16];        // message blocks

  var p0 = 0x01010000 ^ (kk << 8) ^ nn;

  signal hs[dd+1][8];

  component iv = IV();
  hs[0][0] <== (0x6A09E667F3BCC908 ^ p0);
  for(var i=1; i<8; i++) { hs[0][i] <== iv.out[i]; }

  component compr[dd];

  for(var k=0; k<dd; k++) {

    var f = (k == dd-1);                   // is it the final block?
    var t = (f) ? (ll) : ((k+1)*128);      // offset counter
    compr[k] = CompressionF( t , f );

    for(var j=0; j<16; j++) { 
      var acc = 0;
      for(var q=0; q<8; q++) {
        var u = k*128 + j*8 + q;
        if (u < ll) { acc += inp_bytes[u] * (256**q); }
      }
      blocks[k][j] <== acc;
    }

    compr[k].h   <== hs[k];
    compr[k].m   <== blocks[k];
    compr[k].out ==> hs[k+1];
  }

  var nw = (nn + 7) \ 8;      // how many qwords in the output (ceil division)

  for(var j=0; j<nw; j++) {  hs[dd][j] ==> hash_words[j]; }

  component tbs[nw];
  for(var j=0; j<nw; j++) {
    tbs[j] = ToBits(64);
    tbs[j].inp <== hash_words[j];
    for(var i=0; i<64; i++) {
      tbs[j].out[i] ==> hash_bits[j*64+i];
    }    
  }

  for(var j=0; j<nn; j++) {
    var acc = 0;
    for(var i=0; i<8; i++) { acc += hash_bits[j*8+i] * (2**i); }
    hash_bytes[j] <== acc;
  }

}

//------------------------------------------------------------------------------
