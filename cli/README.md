### Commands

Run `cargo run --help` or `cargo run -- <command> --help` for detailed information about each command.

All hex inputs accept an optional `0x` prefix. All hex outputs include the `0x` prefix.

### generate-seed

Generate a 32-byte random hex-encoded seed.

```console
$ cargo run --quiet -- generate-seed ; echo
0x9fb87a5bacb1c54b2e770d6d091da4c04797c1cd760d765ddb026ec3d703d5b2
```

### hkdf

Derive a 32-byte PrivateKey from a seed using HKDF-SHA256.

From the seed above:

```console
$ echo "0x9fb87a5bacb1c54b2e770d6d091da4c04797c1cd760d765ddb026ec3d703d5b2" | cargo run --quiet -- hkdf
0x7be162d67564e3b4c09655baaabecc3725748133e33ab971e565737f189f3f43
```

**From file:**
```console
$ cargo run --quiet -- hkdf --file seed.hex
```

**From stdin:**
```console
$ cargo run --quiet -- hkdf < seed.hex
```

### scalar

Convert a scalar value to its BLS12-381 scalar representation (decimal output).

Accepts input as either:
- Hex with `0x` prefix (raw 32-byte private key)
- Decimal number (without prefix)

The command validates that:
- The input is a valid scalar within the curve order range

From the private key derived above:

```console
$ echo "0x7be162d67564e3b4c09655baaabecc3725748133e33ab971e565737f189f3f43" | cargo run --quiet -- scalar
30417370258289878983951032069403093024210548576862328133794263911723866186107
```

**With decimal input:**
```console
$ echo "1234" | cargo run --quiet -- scalar
1234
```

**From file:**
```console
$ cargo run --quiet -- scalar --prv private_key.hex
```

**From stdin:**
```console
$ cargo run --quiet -- scalar < private_key.hex
```

### pk

Generate a BLS12-381 public key (G1 point) from a 32-byte private key.

The command validates that:
- The input is exactly 32 bytes (64 hex characters)
- The scalar is within the valid curve order range

From the private key derived above:

```console
$ echo "0x7be162d67564e3b4c09655baaabecc3725748133e33ab971e565737f189f3f43" | cargo run --quiet -- pk
0xab21260f2c9d1fb30a46aec117e8c4a0f65f9a8f5b177361c3680da3097eb448b3eb6d0960776f73f4e5bb41d1256371
```

**From file:**
```console
$ cargo run --quiet -- pk --prv private_key.hex
```

**From stdin:**
```console
$ cargo run --quiet -- pk < private_key.hex
```

### sig

Generate a BLS signature (G2 point) from a private key and message.

The command validates that:
- The private key is exactly 32 bytes (64 hex characters)
- The scalar is within the valid curve order range

**Parameters:**
- `--prv` - Private key (from stdin or file)
- `--msg` - Message to sign (required)
- `--dst` - Domain separation tag (optional, defaults to empty)
- `--aug` - Augmentation data (optional, defaults to empty)

**What are dst and aug?**
- `dst` (Domain Separation Tag): A byte string that distinguishes between different protocol uses of the hash-to-curve algorithm. This prevents signatures from one context being valid in another.
- `aug` (Augmentation Data): Additional data that can be included in the signature computation. This is often used for additional context or metadata.

From the private key derived above:

```console
$ echo "0x7be162d67564e3b4c09655baaabecc3725748133e33ab971e565737f189f3f43" | cargo run --quiet -- sig --msg "hello world"
0xa00ac57c24c5ec4db94fe1fee003f7dd15c100041cafba26ba97c0c6e18e04106c4d0dbd03ab5ba6c08ccea14a9ddc5c06d326a27134b6d150343064697bd1d9ed8883b1cdc60fe97baf7d67da28a1e0f63f0456deb99987389183b94ef60798
```

**From file with private key and message:**
```console
$ cargo run --quiet -- sig --prv private_key.hex --msg "hello world"
```

**With domain separation tag (dst) and augmentation (aug):**
```console
$ cargo run --quiet -- sig --prv private_key.hex --msg "hello" --dst "domain" --aug "extra"
```

**Note:** Both `--dst` and `--aug` are optional and default to empty strings if not provided. Different values for these parameters will produce different signatures.

### mul

Multiply a BLS12-381 point (G1 or G2) by a scalar value.

The command validates that:
- Exactly one of `--g1` or `--g2` is provided
- The point is a valid compressed point for the chosen group
- The scalar is within the valid curve order range

**Parameters:**
- `--g1` or `--g2` - Group selection (mutually exclusive, required)
- `--point` - Point (from stdin or file, as hex)
- `--scalar` - Scalar value (hex with `0x` prefix, or decimal without prefix)

**Examples:**

Multiply the G1 generator by scalar 1:
```console
$ echo "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb" | cargo run --quiet -- mul --g1 --scalar "0x0100000000000000000000000000000000000000000000000000000000000000"
```

Using decimal scalar:
```console
$ echo "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb" | cargo run --quiet -- mul --g1 --scalar "1"
```

Multiply the G2 generator by scalar 1:
```console
$ echo "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8" | cargo run --quiet -- mul --g2 --scalar "0x0100000000000000000000000000000000000000000000000000000000000000"
```

**From file:**
```console
$ cargo run --quiet -- mul --g1 --point point.hex --scalar "0xscalar_hex"
```

**From stdin:**
```console
$ cargo run --quiet -- mul --g2 --scalar "0xscalar_hex" < point.hex
```

### add

Add two BLS12-381 points (G1 or G2 group) together.

The command validates that:
- Exactly one of `--g1` or `--g2` is provided
- Both points are valid compressed points for the chosen group
- The special value `identity` can be used for either point to denote the identity element

**Parameters:**
- `--g1` or `--g2` - Group selection (mutually exclusive, required)
- `--point_left` - Left point (from stdin or file, as hex, or `identity`)
- `--point_right` - Right point (required, as hex, or `identity`)

**Examples:**

Add the G1 generator to itself (source from stdin):
```console
$ echo "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb" | cargo run --quiet -- add --g1 --point_right "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
```

Add G2 identity + G2 generator = G2 generator:
```console
$ cargo run --quiet -- add --g2 --point_left "identity" --point_right "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
```

**From file:**
```console
$ cargo run --quiet -- add --g1 --point_left point.hex --point_right "point_hex"
```

**From stdin:**
```console
$ cargo run --quiet -- add --g2 --point_right "point_hex" < point.hex
```

### compress

Compress (validate and canonicalize) a BLS12-381 point (G1 or G2).

Accepts both compressed (48/96 bytes) and uncompressed (96/192 bytes) input. The output is always the compressed form. This is useful for:
- Validating that a point is on the curve
- Converting from uncompressed to compressed format
- Canonicalizing a compressed point

The command validates that:
- Exactly one of `--g1` or `--g2` is provided
- The point is a valid point for the chosen group
- The input has the correct length for the chosen group

**Parameters:**
- `--g1` or `--g2` - Group selection (mutually exclusive, required)
- `--point` - Point (from stdin or file, as hex, or `identity`)

**Examples:**

Validate and re-compress the G1 generator:
```console
$ echo "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb" | cargo run --quiet -- compress --g1
```

Compress the G2 generator:
```console
$ echo "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8" | cargo run --quiet -- compress --g2
```

Compress the identity element:
```console
$ cargo run --quiet -- compress --g1 --point identity
```

**From file:**
```console
$ cargo run --quiet -- compress --g1 --point point.hex
```

### uncompress

Uncompress (decompress) a BLS12-381 point (G1 or G2).

Takes a compressed point (48 bytes for G1, 96 bytes for G2) and outputs the
uncompressed form (96 bytes for G1, 192 bytes for G2). The output is always
the full x and y coordinates as hex.

The command validates that:
- Exactly one of `--g1` or `--g2` is provided
- The point is a valid compressed point for the chosen group
- The input has the correct length for the chosen group

**Parameters:**
- `--g1` or `--g2` - Group selection (mutually exclusive, required)
- `--point` - Point (from stdin or file, as hex, or `identity`)

**Examples:**

Uncompress the G1 generator:
```console
$ echo "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb" | cargo run --quiet -- uncompress --g1
```

Uncompress the G2 generator:
```console
$ echo "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8" | cargo run --quiet -- uncompress --g2
```

Uncompress the identity element:
```console
$ cargo run --quiet -- uncompress --g1 --point identity
```

**From file:**
```console
$ cargo run --quiet -- uncompress --g1 --point point.hex
```

### Practical example: solving x + y = 23

Show that `10 * G + 13 * G = 23 * G` for both G1 and G2 groups, demonstrating the homomorphic property of BLS12-381 points. The special value `generator` can be used with `--point` to refer to the group generator.

**G1:**

Compute `10 * G1` and `13 * G1`, then add them and verify the result equals `23 * G1`:

```console
$ TEN=$(cargo run --quiet -- mul --g1 --point generator --scalar "10")
$ THIRTEEN=$(cargo run --quiet -- mul --g1 --point generator --scalar "13")

$ echo "$TEN"
0xaf81da25ecf1c84b577fefbedd61077a81dc43b00304015b2b596ab67f00e41c86bb00ebd0f90d4b125eb0539891aeed

$ echo "$THIRTEEN"
0x851f8a0b82a6d86202a61cbc3b0f3db7d19650b914587bde4715ccd372e1e40cab95517779d840416e1679c84a6db24e

$ echo "$TEN" | cargo run --quiet -- add --g1 --point_right "$THIRTEEN"
0x8c8b694b04d98a749a0763c72fc020ef61b2bb3f63ebb182cb2e568f6a8b9ca3ae013ae78317599e7e7ba2a528ec754a

$ cargo run --quiet -- mul --g1 --point generator --scalar "23"
0x8c8b694b04d98a749a0763c72fc020ef61b2bb3f63ebb182cb2e568f6a8b9ca3ae013ae78317599e7e7ba2a528ec754a
```

The output of `10 * G1 + 13 * G1` matches `23 * G1`, confirming that scalar multiplication distributes over point addition in G1.

**G2:**

The same property holds for G2:

```console
$ cargo run --quiet -- mul --g2 --point generator --scalar "10"
0xafb665f5a7559cb0fa1300048a0e6f1ab5547226e86f8e752dd13c28eda4168492e3d3bf2f8a6b230dd57f79b1afa9911796abe0d9e4a703962be528e6a5cb65c60725886f925db0e2a89107ec248bb39fa332bc63bd91d28ae66e0dfce8f754

$ cargo run --quiet -- mul --g2 --point generator --scalar "13"
0x8bf78a97086750eb166986ed8e428ca1d23ae3bbf8b2ee67451d7dd84445311e8bc8ab558b0bc008199f577195fc39b7152110e866f1a6e8c5348f6e005dbd93de671b7d0fbfa04d6614bcdd27a3cb2a70f0deacb3608ba95226268481a0be7c

$ cargo run --quiet -- mul --g2 --point generator --scalar "23"
0x901e147f8bd7682b47b3a6cc0c552c26ce90b9ce0daef21f7f634b3360483afa14a11e6745e7de01a35c65b396a1a127131747485cce9a5c32837a964b8c0689ff70cb4702c6520f2220ab95192d73ae9508c5b998ffb0be40520926846ce3f1

$ TEN=$(cargo run --quiet -- mul --g2 --point generator --scalar "10")
$ THIRTEEN=$(cargo run --quiet -- mul --g2 --point generator --scalar "13")
$ echo "$TEN" | cargo run --quiet -- add --g2 --point_right "$THIRTEEN"
0x901e147f8bd7682b47b3a6cc0c552c26ce90b9ce0daef21f7f634b3360483afa14a11e6745e7de01a35c65b396a1a127131747485cce9a5c32837a964b8c0689ff70cb4702c6520f2220ab95192d73ae9508c5b998ffb0be40520926846ce3f1
```

The output of `10 * G2 + 13 * G2` matches `23 * G2`, confirming the same distributive property in G2.

### Compress and uncompress

All `mul`, `add`, `compress`, and `uncompress` commands work with compressed points. For example, the result `0x8c8b694b...` from the `x + y = 23` G1 example above is already a compressed point — it can be used directly in `compress` and `uncompress`.

Demonstrating this with `23 * G1` from the equation:

```console
$ TWENTY_THREE=$(cargo run --quiet -- mul --g1 --point generator --scalar "23")

$ echo "$TWENTY_THREE"
0x8c8b694b04d98a749a0763c72fc020ef61b2bb3f63ebb182cb2e568f6a8b9ca3ae013ae78317599e7e7ba2a528ec754a

$ echo "$TWENTY_THREE" | cargo run --quiet -- uncompress --g1
0x0c8b694b04d98a749a0763c72fc020ef61b2bb3f63ebb182cb2e568f6a8b9ca3ae013ae78317599e7e7ba2a528ec754a79e21c0eb0c87e3e2a44f8f5ac0e790bf114393a2c792f90b1e2a58a7b3c8a6f2c30e19f1112d6ca9281422e77ae0ea

$ echo "$TWENTY_THREE" | cargo run --quiet -- compress --g1
0x8c8b694b04d98a749a0763c72fc020ef61b2bb3f63ebb182cb2e568f6a8b9ca3ae013ae78317599e7e7ba2a528ec754a
```

The commands convert between compressed and uncompressed point representations:

- **Compressed** (48 bytes for G1, 96 bytes for G2): Compact form storing only the x-coordinate plus a sign bit. Used for storage and transmission.
- **Uncompressed** (96 bytes for G1, 192 bytes for G2): Full affine coordinates (x, y). Needed for certain operations like pairings.

`compress` also serves as a **validation** tool: it accepts both compressed and uncompressed input, verifies the point is on the curve, and outputs the canonical compressed form. This is useful for ensuring data integrity.

**G2 example:**

```console
$ COMPRESSED=$(echo "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8" | cargo run --quiet -- compress --g2)

$ echo "$COMPRESSED"
0x93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8

$ UNCOMPRESSED=$(echo "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8" | cargo run --quiet -- uncompress --g2)

$ echo "$UNCOMPRESSED"
0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801

$ echo "$UNCOMPRESSED" | cargo run --quiet -- compress --g2
0x93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8
```

**Identity:**

The identity element (point at infinity) is also handled:

```console
$ cargo run --quiet -- compress --g1 --point identity
0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

$ cargo run --quiet -- uncompress --g1 --point identity
0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```
