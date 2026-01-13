# BLS multi-signatures cryptographic tools

## Contents
1. [Introduction](#high-level-introduction)
2. [BLS12-381 Elliptic curve](#bls-elliptic-curve)

## High level introduction

**BLS** abbreviation stands for names of inventors of the scheme, ie., Boneh-Lynn-Shacham, that proposed the scheme in the
(Short signatures from the Weil pairing)[https://mit6875.github.io/FA23HANDOUTS/boneh-lynn-shacham.pdf] paper.
The scheme works for pairings-friendly elliptic curves within which two groups are chosen,  _G1_ and _G2_, with generators _g1_ and _g2_, respectively.
The secret key *sk* is then randomly picked between _1_ and _order(G1)_. The corresponding public key is

$pk = sk*g_2$

Having hashing function, $H(msg)=elem_1$ we can get signature,

$sig = sk*H(msg)$

Given a pairing, _e_, verification is checking the equality

$e(H(m), pk) == e(sig, g_2)$

Please notice that in any pairing we have elements of two groups, _G1_ and _G2_.
And due to bilinearity property of the pairing we the following holding

$e(H(m), pk) = e(H(m)m sk*g_2) = e(sk*H(m), g_2) = e(sig, g_2)$

The choices of representation of the different entities are not random and done by purpose. _G2_ is defined over the quadratic
extention of the field and hence the storage demands are larger for _G2_. The arithmetic requirements are harsher for _G2_ in comparison with _G1_.
If we are to store all public keys in application then it would be tempting to represent them in _G1_. If we are to store signatures then it is advantageous to
stick to the scheme proposed above. Especially, if **public keys could be aggregated**.
Another performance dimension to ponder is verification, as normally pairing operation is costly. Especially if we compare it to other elliptic curve signature schemes like
_Schnorr_ or _EdDSA_. However, as BLS allows for **signature aggregation**, not so straightforward in other schemes mentioned, the comparison picture changes dramatically in favor of BLS,
especially for multi-signature cases.


## BLS elliptic curve

The elliptic curve BLS12-381 we are using here is currently in (IETF draft 12)[https://datatracker.ietf.org/doc/draft-irtf-cfrg-pairing-friendly-curves/12/] stage of ratification.
