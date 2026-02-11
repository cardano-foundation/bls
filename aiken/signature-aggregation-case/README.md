# Signature aggregation case

In multi signature aggregation case, we have multiple parties that participate in
message signing and verification. Elliptic cryptography is used here (bls12-381)which is natively supported.
Each party is having __(sk_i, pk_i)__ key pair and is signing __msg_i__ .
As a consequence, we have signatures __sig_i__ produced, ie.,

```math
sig_i=sign(sk_i,msg_i) 
```

Signature aggregation means we can, aggregate all __sig_i__, **make shorter** than the sum of all signatures engaged,
in such a way that a resultant signature, __sig_(aggr)__ , can be used in verfication stage:

```
verResult = verify([pk_1, ... , pk_n], [msg_1, ... , msg_n], sig_(aggr))
```

Thanks to that verification is quicker and has lower byte imprint.

# Security considerations:

We can have two cases here,

## each __msg_i__ is unique

Basic primitives are **secure** and one can use

```aiken
        bls/g2_basic.{aggregate_signatures, aggregate_verify, skToPk, sign}
```

## there is duplication of __msg_i__ for some i's or we do not know it is the case

Basic primitives are susceptible to __rogue-key attack__ and we need to be careful
and make sure duplicate messages are not allowed. For this, we need to use

```aiken
        bls/g2_basic.{aggregate_signatures, aggregate_distinct_verify, skToPk, sign}
```

__aggregate_distinct_verify__ make sure each message is unique before verification.



