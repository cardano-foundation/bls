# BLS multi-signatures cryptographic tools

## Contents
1. [Introduction](#high-level-introduction)
2. [BLS12-381 Elliptic curve overview](#bls-elliptic-curves-overview)
3. [BLS12-381 Elliptic curve golden in sagemath](#bls12-381-elliptic-curve-golden)

## High level introduction

**BLS** abbreviation stands for names of inventors of the scheme, ie., Boneh-Lynn-Shacham, that proposed the scheme in the
[Short signatures from the Weil pairing](https://mit6875.github.io/FA23HANDOUTS/boneh-lynn-shacham.pdf) paper.
The scheme works for pairings-friendly elliptic curves within which two groups are chosen,  _G1_ and _G2_, with generators _g1_ and _g2_, respectively.
The secret key *sk* is then randomly picked between _1_ and _order(G1)_. The corresponding public key is

$pk=sk*g_2$

Having hashing function, $H(msg)=elem_1$ we can get signature,

$sig=sk*H(msg)$

Given a pairing, _e_, verification is checking the equality

$e(H(m),pk)==e(sig,g_2)$

Please notice that in any pairing we have elements of two groups, _G1_ and _G2_.
And due to bilinearity property of the pairing we the following holding

$e(H(m),pk)=e(H(m),sk*g_2)$
$e(H(m),sk*g_2)=e(sk*H(m),g_2)$
$e(sk*H(m),g_2)=e(sig, g_2)$

The choices of representation of the different entities are not random and done by purpose. _G2_ is defined over the quadratic
extention of the field and hence the storage demands are larger for _G2_. The arithmetic requirements are harsher for _G2_ in comparison with _G1_.
If we are to store all public keys in application then it would be tempting to represent them in _G1_. If we are to store signatures then it is advantageous to
stick to the scheme proposed above. Especially, if **public keys could be aggregated**.
Another performance dimension to ponder is verification, as normally pairing operation is costly. Especially if we compare it to other elliptic curve signature schemes like
_Schnorr_ or _EdDSA_. However, as BLS allows for **signature aggregation**, not so straightforward in other schemes mentioned, the comparison picture changes dramatically in favor of BLS,
especially for multi-signature cases.


## BLS elliptic curves overview

Although the same abbreviation, BLS here, stands for Barreto-Lynn-Scott. The family of curves was intruduced in this [seminal paper]().
BLS12-381 curve was proposed by [Sean Bowe in the context of ZCash](https://electriccoin.co/blog/new-snark-curve/).
The usage of this curve was adopted in number of other blockchains, like Ethereum 2.0, Skale, Algorand, Dfinity or Chia.
There is also support of this in [cardano-crypto-class](https://github.com/IntersectMBO/cardano-base/tree/master/cardano-crypto-class) and the curve it exposed in [aiken from 3.0](https://aiken-lang.github.io/stdlib/aiken/crypto.html). The great introduction and motivation for this curve was written in the blog post [BLS12-381 For The Rest Of Us](https://hackmd.io/@benjaminion/bls12-381#Motivation).
It is especially worth mentioning and repeating that the elliptic curve BLS12-381 is currently in [IETF draft revision 12](https://datatracker.ietf.org/doc/draft-irtf-cfrg-pairing-friendly-curves/12/) stage of ratification.

## BLS12-381 elliptic curve golden

The golden are generated using _SageMath_. In order to run it do the following:
Download the latest image from docker hub and run the image in Linux CLI:

```bash
$ docker image pull sagemath/sagemath:latest
$ docker run -it sagemath/sagemath:latest
┌────────────────────────────────────────────────────────────────────┐
│ SageMath version 10.6, Release Date: 2025-03-31                    │
│ Using Python 3.12.5. Type "help()" for help.                       │
└────────────────────────────────────────────────────────────────────┘
sage: ZZ(1234)
1234
sage: ZZ.random_element(10**10)
4134169080
sage: quit
```