# Public key aggregation case using BLS12-381 aiken primitives

Public key aggregation means we can, aggregate all __pk_i__, **make shorter** than the sum of all public key engaged,
in such a way that a resultant public key, __pk_(aggr)__ , can be used in verfication stage:

```math
verResult = verify([pk_(aggr)], [msg, ... , msg], [sk_1, ... , sk_n])
```

where each party is having __(sk_i, pk_i)__ key pair and is signing the same  __msg__ .

Also, both aggregations, ie., public key and signature, can be used together:

```math
verResult = verify([pk_(aggr)], [msg, ... , msg], sig_(aggr))
```

The method, except the requirement for the same message each party is signing, only works (ie. is practical) for Basic BLS case.
(For more rationale and explanation refer to [tests](./validators/placeholder.ak))

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