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

```math
$e(H(m),pk)=$
$=e(sk*H(m),g_2)=$
$=e(sig, g_2)$
```

The choices of representation of the different entities are not random and done by purpose. _G2_ is defined over the quadratic
extention of the field and hence the storage demands are larger for _G2_. The arithmetic requirements are harsher for _G2_ in comparison with _G1_.
If we are to store all public keys in application then it would be tempting to represent them in _G1_. If we are to store signatures then it is advantageous to
stick to the scheme proposed above. Especially, if **public keys could be aggregated**.
Another performance dimension to ponder is verification, as normally pairing operation is costly. Especially if we compare it to other elliptic curve signature schemes like
_Schnorr_ or _EdDSA_. However, as BLS allows for **signature aggregation**, not so straightforward in other schemes mentioned, the comparison picture changes dramatically in favor of BLS,
especially for multi-signature cases.


## BLS elliptic curves overview

Although the same abbreviation, BLS here, stands for Barreto-Lynn-Scott. The family of curves was introduced in this [seminal paper](https://eprint.iacr.org/2002/088.pdf).
BLS12-381 curve was proposed by [Sean Bowe in the context of ZCash](https://electriccoin.co/blog/new-snark-curve/).
The usage of this curve was adopted in number of other blockchains, like Ethereum 2.0, Skale, Algorand, Dfinity or Chia.
There is also support of this curve in Cardano, see for example, [cardano-crypto-class](https://github.com/IntersectMBO/cardano-base/tree/master/cardano-crypto-class) and the curve is exposed also in [aiken from 3.0 release](https://aiken-lang.github.io/stdlib/aiken/crypto.html). The great introduction and motivation for this curve was written in the blog post [BLS12-381 For The Rest Of Us](https://hackmd.io/@benjaminion/bls12-381#Motivation).
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

Definition of the `g1` and `g2` generators of BLS12-381 are as follows:

```sagemath
age: p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
sage: F = GF(p)
sage: G1 = EllipticCurve(F, [0,4])
sage: G1.order()
4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129030796414117214202539
sage: F2.<t> = GF(p^2, modulus=[1, 0, 1])
sage: G2 = EllipticCurve(F2, [0, 4 * (1 + t)])
sage: 
sage: # generator of G1
sage: g1_x = 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb
sage: g1_y = 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1
sage: g1 = G1(g1_x, g1_y)
sage: g1
(3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507 : 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569 : 1)
sage: 
sage: # generator of G2
sage: g2_x = F2(0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8 + \
....: 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e * t)
sage: g2_y = F2(0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801 + \
....: 0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be * t)
sage: g2 = G2(g2_x, g2_y)
sage: g2
(3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758*t + 352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160 : 927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582*t + 1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905 : 1)
```