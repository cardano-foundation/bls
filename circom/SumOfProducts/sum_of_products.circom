pragma circom 2.0.0;

// SumOfProducts: a 4-gate "hello world" circuit
//
//   t1 = a * b
//   t2 = c * d
//   t3 = e * f
//   t4 = g * h
//   out = t1 + t2 + t3 + t4
//
// The circuit proves knowledge of eight secret factors whose
// pairwise products sum to a public output.
//
// Witness ordering: [1, out, a, b, c, d, e, f, g, h, t1, t2, t3, t4]

template SumOfProducts() {
    signal input a;
    signal input b;
    signal input c;
    signal input d;
    signal input e;
    signal input f;
    signal input g;
    signal input h;

    signal t1;
    signal t2;
    signal t3;
    signal t4;
    signal output out;

    t1 <== a * b;
    t2 <== c * d;
    t3 <== e * f;
    t4 <== g * h;
    out <== t1 + t2 + t3 + t4;
}

component main = SumOfProducts();
