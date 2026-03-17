# Signature aggregation case using BLS12-381

In multi signature aggregation case, we have multiple parties that participate in
message signing and verification. Elliptic cryptography is used here (bls12-381) which is natively supported.
Each party is having __(sk_i, pk_i)__ key pair and is signing __msg_i__ .
As a consequence, we have signatures __sig_i__ produced, ie.,

```math
sig_i=sign(sk_i,msg_i) 
```

Signature aggregation means we can, aggregate all __sig_i__, **make shorter** than the sum of all signatures engaged,
in such a way that a resultant signature, __sig_(aggr)__ , can be used in verfication stage:

```math
verResult = verify([pk_1, ... , pk_n], [msg_1, ... , msg_n], sig_(aggr))
```

Thanks to that verification is quicker and has lower byte imprint.

# Security considerations:

We can have two cases here,

## 1. Each __msg_i__ is unique

Basic primitives are **secure** and one can use

```aiken
        use bls/g1/basic.{aggregate, aggregate_verify, sign}
```

## 2. There is the duplication of __msg_i__ for some i's or we do not know if it is the case

Basic primitives are susceptible to __rogue-key attack__ and we need to be careful
and make sure duplicate messages are not allowed. For this, we need to use

```aiken
        bls/g2_basic.{aggregate_verify}
```

__aggregate_verify__ make sure each message is unique before verification.

### What is the nature of problem here?

Let's assume we have __(sk1, pk1)__, __(sk2, pk2)__ and __(sk3, pk3)__ .
Third party is malicious here and constructs public key that offsets the honest keys of other
participants:

```math
pk_(rogue) = pk3 - (pk1 + pk2)
```

After key aggregation:

```math
 pk1 + pk2 + pk_(rogue) = pk3
```

This allows the attacker to produce a single valid signature with __pk3__ that verifies all participants contributed,
of course, if the message to be signed is the same.

Hence, distinct-message enforcement needs to be applied as exemplified by `aggregate_verify`.
If one want to see the problem there is `core_aggregate_verify` low level function, without message distincness check.

There are two other mitigations at hand, namely PoP and augmented signing.

## Augmented BLS signing mode

In order to avoid `rogue-key attack` the signed message altered to the following:

```math
H(pk || message)
```

Meaning the signer’s public key is prepended to the message before hashing,
binding the public key to the signature.

In order to enable this, we need to import

```aiken
        use bls/g1/aug.{aggregate, aggregate_verify,sign}
```

Thanks to that, the following verification is possible:

```aiken
        aug_bls.aggregate_verify([pk1,pk2,pk3], [message,message,message], sig_aggr)
```

## Proof of Possession (PoP) BLS

PoP BLS is augmenting the BLS scheme with additional goodies.
Each participant during key registration needs to prove that actually controls the private key corresponding to the registered public key.

In order to enable this, we need to import

```aiken
        use bls/g1/pop.{aggregate, aggregate_verify, pop_prove, pop_verify, sign}
```

## Summary of situation

| Scenario | Basic BLS | Augmented BLS	| PoP BLS |
|----------|-----------|----------------|---------|
| not unique messages +'core_aggregate_verify'| 	❌ unsafe  |	✅ safe |	✅ safe |
| not unique messages + `aggregate_verify([pks],[msgs],sig_aggr)` |	❌ unsafe as validation is not passing |	✅ safe |	✅ safe |
| unique messages + `aggregate_verify([pks],[msgs],sig_aggr)` |	✅ safe	| ✅ safe	| ✅ safe |


## Executive summary with IETF recommendations

- Aggregating signatures does not increase security risk
- In the case when messages are unique all setups are safe
- In the case when messages are NOT unique only augmented and PoP setups are safe

## Building

```sh
aiken build
```

## Testing
 
To run all tests, simply do:

```sh
aiken check
```

To run only tests matching the string `foo`, do:

```sh
aiken check -m foo
```

## Resources

Find more on [Aiken's user manual](https://aiken-lang.org) and the recommended library for the scheme [ilap/bls](https://github.com/ilap/bls).