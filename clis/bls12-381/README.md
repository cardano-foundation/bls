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

### neg

Compute the additive inverse (negation) of a BLS12-381 point (G1 or G2).

The command validates that:
- Exactly one of `--g1` or `--g2` is provided
- The point is a valid point for the chosen group
- The input has the correct length for the chosen group

Negation satisfies: `point + neg(point) = identity` for all points.

**Parameters:**
- `--g1` or `--g2` - Group selection (mutually exclusive, required)
- `--point` - Point (from stdin, file, or direct hex, or `identity`/`generator`)

**Examples:**

Negate the G1 generator:
```console
$ echo "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb" | cargo run --quiet -- neg --g1
0xb7f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb
```

Negate the G2 generator:
```console
$ echo "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8" | cargo run --quiet -- neg --g2
0xb3e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8
```

Negate the identity element (returns identity):
```console
$ cargo run --quiet -- neg --g1 --point identity
0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

**Verification: G1 generator plus its negation equals identity:**
```console
$ G=$(echo "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb" | cargo run --quiet -- neg --g1)
$ echo "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb" | cargo run --quiet -- add --g1 --point_right "$G"
0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

**From file:**
```console
$ cargo run --quiet -- neg --g1 --point point.hex
```

**From stdin:**
```console
$ cargo run --quiet -- neg --g2 < point.hex
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

### pairing

Compute the optimal Ate pairing `e(G1, G2)` using the miller loop. Both points must be in **uncompressed** form (96 bytes / 192 hex chars for G1, 192 bytes / 384 hex chars for G2). The output is a 1152-hex-char (576-byte) `Fp12` element.

The `--g1` and `--g2` flags accept the point hex directly. If one is omitted, that point is read from stdin (or from a file via `--g1-file` / `--g2-file`).

**Using the `x + y = 23` G1 result with G2 generator:**

First, get the uncompressed G2 generator. Then run `e(23*G1, G2_gen)`:

```console
$ G2_UNCOMPRESSED=$(cargo run --quiet -- uncompress --g2 --point generator)

$ TWENTY_THREE=$(cargo run --quiet -- mul --g1 --point generator --scalar "23")
$ TWENTY_THREE_UNCOMPRESSED=$(echo "$TWENTY_THREE" | cargo run --quiet -- uncompress --g1)

$ echo "$TWENTY_THREE_UNCOMPRESSED" | cargo run --quiet -- pairing --g2 "$G2_UNCOMPRESSED"
0xc5851fa033e47219382577fd762bd397f9cd6bc96f54cec81406d466733ef6ce80378481273411a625d8c63f8a44f31395699d2eb03163d27d7e79f782a4689d92ea398d24299b9caa0731e1a21c80f466b0bcbd32076ca1780436baafa43c0841b61609db61e2590d963eb2f4b61627459cbda0105be5c8a8ed4d9cd90bdb0bc5aafd57bf9ef88c5e7a779e92b7d612355fe1b08851c85f6563098f3a6ea0342cd62ae0a62631db0b999a7da95a6ffc10c289ebf5552fa189886f923a70231778878271298f58938575ab11865bf643df9f27ecf5aa8331f69dc98ae1d773fab0994ca6a676e1641f8f38588ca79f1712ef2aca110a2a676bf1a32ab5b9110d6e059d69d01244a4a55b1a2277011dc02955736cdecee06639c3dd9f1ea7f50579c662b0a1880ad30483fc355d6ac55a0d291fa8a634c8d0c70737dac23054cdf00a5080f77fc2f0ae2ed7e2a65d240956511b7976062e9f13fe184923c8d1e2f41b563c9f459e4cc1e3d3b9535ee8a32000a7211e120a82cc9ac5418361af15b13a99248c65957cb986a81c7238eb73bc34744749d756528b4a50ea0219a48b6dce860cf8d3a304aa6e68fb874aa61826cf20b91be783bb4539a792ac77522aa046f0949fe50efcf7586078f3cd5871f645f9821b06c17c67e5db9faa47f80357e63461a5db78806e8a99439aecd71c6637991a9a59aab144ee42082ff6a0c9fadf05b6e39b158ec23ff14a0dba860cb1ff526aa0f20fe86c901a7248ca94761485b0033e188375e2e4ce40ddaf67f5fca526e5d2966d9a42221f86499f7e19
```

**Pairing with identity:**

`e(identity, anything) = e(anything, identity) = 1` (the identity element in GT):

```console
$ G1_ID_UNCOMPRESSED=$(cargo run --quiet -- uncompress --g1 --point identity)
$ G2_ID_UNCOMPRESSED=$(cargo run --quiet -- uncompress --g2 --point identity)
$ G2_UNCOMPRESSED=$(cargo run --quiet -- uncompress --g2 --point generator)
$ G1_UNCOMPRESSED=$(cargo run --quiet -- uncompress --g1 --point generator)

$ echo "$G1_ID_UNCOMPRESSED" | cargo run --quiet -- pairing --g2 "$G2_UNCOMPRESSED"
0xfdff02000000097602000cc40b00f4ebba58c7535798485f455752705358ce776dec56a2971a075c93e480fac35ef61500a08708312eade1efb9f6c2ee4d4a6a25eb74abae0954e760d32ecedf7fe8c66196cf887d28c7c00e58e0a6b4c400b47c9d7a4e3bc88c58d300358ae4d03201c7e6d4b139cc11b1db1d30ab66965e9c791af75167572e3317eafeda1b826b13140f866469a68cb324a0199c1bd7b42dfd52c60a06a9c24ae2d86c8efb256e494f78970a2fba8491dc8005f1de66a481d3e7dd781c9b1f57e65ac4855a8932ed6b464df0ac7fd5dc3f7f8f8b5ba8a48a9d4431227fbcc50ec44c5f43e8fe24fa9d3df38f6f795705e2f1d608de324d15b8cf356e70ffffba63f56ea68baa747b8463e5d3f5ffdaebc669560fa38bdf7b8bba3ecf79dc58d1483174b49699d1df04e816e03870eb1500cf25e8bb2069e54232273b6dc5c603321797a8801b51f0ba0e81e3715f1120082d25f71f41f0f800c8b8e8aac133e68faccb851ae0eee16e53b2df5b7c126389010a2bea83d77f18b3e5b4ede0a4f32b70f01cf3bc20877c850da86c27cae3e06e83f20a3ea683eca9105ee627881f4f8c7f19446989b6563dbfb8bbcfd510dc9c065faf4f6502e3f01607e6ea05255065b40c9f1102cfbb914d767b48c77ef254cb68b90b116449f62d5f20168cf61b6e282a54eb244e844f7399e4ec79de135fa29904bddeb18926bde3c1266cb7d9e3d80d0a960a56b9931bab51f1502302362011

$ echo "$G1_UNCOMPRESSED" | cargo run --quiet -- pairing --g2 "$G2_ID_UNCOMPRESSED"
0xfdff02000000097602000cc40b00f4ebba58c7535798485f455752705358ce776dec56a2971a075c93e480fac35ef61500a08708312eade1efb9f6c2ee4d4a6a25eb74abae0954e760d32ecedf7fe8c66196cf887d28c7c00e58e0a6b4c400b47c9d7a4e3bc88c58d300358ae4d03201c7e6d4b139cc11b1db1d30ab66965e9c791af75167572e3317eafeda1b826b13140f866469a68cb324a0199c1bd7b42dfd52c60a06a9c24ae2d86c8efb256e494f78970a2fba8491dc8005f1de66a481d3e7dd781c9b1f57e65ac4855a8932ed6b464df0ac7fd5dc3f7f8f8b5ba8a48a9d4431227fbcc50ec44c5f43e8fe24fa9d3df38f6f795705e2f1d608de324d15b8cf356e70ffffba63f56ea68baa747b8463e5d3f5ffdaebc669560fa38bdf7b8bba3ecf79dc58d1483174b49699d1df04e816e03870eb1500cf25e8bb2069e54232273b6dc5c603321797a8801b51f0ba0e81e3715f1120082d25f71f41f0f800c8b8e8aac133e68faccb851ae0eee16e53b2df5b7c126389010a2bea83d77f18b3e5b4ede0a4f32b70f01cf3bc20877c850da86c27cae3e06e83f20a3ea683eca9105ee627881f4f8c7f19446989b6563dbfb8bbcfd510dc9c065faf4f6502e3f01607e6ea05255065b40c9f1102cfbb914d767b48c77ef254cb68b90b116449f62d5f20168cf61b6e282a54eb244e844f7399e4ec79de135fa29904bddeb18926bde3c1266cb7d9e3d80d0a960a56b9931bab51f1502302362011
```

Both produce the same output — the identity element in GT — confirming that pairing with the identity point always yields the identity in the target group.

**All input modes:**

```console
$ G1_UNCOMPRESSED=$(cargo run --quiet -- uncompress --g1 --point generator)
$ G2_UNCOMPRESSED=$(cargo run --quiet -- uncompress --g2 --point generator)

# G1 from stdin, G2 via --g2
$ echo "$G1_UNCOMPRESSED" | cargo run --quiet -- pairing --g2 "$G2_UNCOMPRESSED"

# G2 from stdin, G1 via --g1
$ echo "$G2_UNCOMPRESSED" | cargo run --quiet -- pairing --g1 "$G1_UNCOMPRESSED"

# Both via --g1 and --g2
$ cargo run --quiet -- pairing --g1 "$G1_UNCOMPRESSED" --g2 "$G2_UNCOMPRESSED"

# Both from files
$ echo "$G1_UNCOMPRESSED" > g1.hex && echo "$G2_UNCOMPRESSED" > g2.hex
$ cargo run --quiet -- pairing --g1-file g1.hex --g2-file g2.hex

### Practical example: solving x × y = 26 using pairings

Beyond linear equations (`x + y = 23`), pairings enable verification of **non-linear** relationships. A prover can prove knowledge of `x` and `y` such that `x × y = 26` without revealing `x` and `y` — by sending **only points** and relying on the bilinearity property of pairings.

**The protocol:**

| Step | Prover knows `x = 13`, `y = 2` | Verifier checks |
|---|---|---|
| 1 | Computes `X = 13 · G1` and `Y = 2 · G2` | — |
| 2 | Sends `X` (G1 point) and `Y` (G2 point) | Receives `X`, `Y` |
| 3 | — | Computes `e(X, Y)` and `e(G1, 26 · G2)` |
| 4 | — | **Accepts** if `e(X, Y) == e(G1, 26 · G2)` |

**Why it works:**

`e(13·G1, 2·G2) = e(G1, G2)^(13·2) = e(G1, G2)^26 = e(G1, 26·G2)`

The pairing's bilinearity guarantees that `e(X, Y) = e(G1, 26·G2)` if and only if `x × y = 26` — without ever revealing `x` or `y`.

**Important:** Pairing requires **uncompressed** points (96 bytes for G1, 192 bytes for G2). Compressed points (48/96 bytes) cannot be used directly.

**Prover: computes X and Y (uncompressed)**

```console
$ G1_UNCOMPRESSED=$(cargo run --quiet -- uncompress --g1 --point generator)
$ G2_UNCOMPRESSED=$(cargo run --quiet -- uncompress --g2 --point generator)

# X = 13 * G1 (uncompressed)
$ X_COMPRESSED=$(cargo run --quiet -- mul --g1 --point generator --scalar "13")
$ echo "$X_COMPRESSED"
0x851f8a0b82a6d86202a61cbc3b0f3db7d19650b914587bde4715ccd372e1e40cab95517779d840416e1679c84a6db24e

$ X=$(echo "$X_COMPRESSED" | cargo run --quiet -- uncompress --g1)
$ echo "$X"
0x051f8a0b82a6d86202a61cbc3b0f3db7d19650b914587bde4715ccd372e1e40cab95517779d840416e1679c84a6db24e0b6a63ac48b7d7666ccfcf1e7de0097c5e6e1aacd03507d23fb975d8daec42857b3a471bf3fc471425b63864e045f4df

# Y = 2 * G2 (uncompressed)
$ Y_COMPRESSED=$(cargo run --quiet -- mul --g2 --point generator --scalar "2")
$ echo "$Y_COMPRESSED"
0xaa4edef9c1ed7f729f520e47730a124fd70662a904ba1074728114d1031e1572c6c886f6b57ec72a6178288c47c335771638533957d540a9d2370f17cc7ed5863bc0b995b8825e0ee1ea1e1e4d00dbae81f14b0bf3611b78c952aacab827a053

$ Y=$(echo "$Y_COMPRESSED" | cargo run --quiet -- uncompress --g2)
$ echo "$Y"
0x0a4edef9c1ed7f729f520e47730a124fd70662a904ba1074728114d1031e1572c6c886f6b57ec72a6178288c47c335771638533957d540a9d2370f17cc7ed5863bc0b995b8825e0ee1ea1e1e4d00dbae81f14b0bf3611b78c952aacab827a0530f6d4552fa65dd2638b361543f887136a43253d9c66c411697003f7a13c308f5422e1aa0a59c8967acdefd8b6e36ccf30468fb440d82b0630aeb8dca2b5256789a66da69bf91009cbfe6bd221e47aa8ae88dece9764bf3bd999d95d71e4c9899
```

**Verifier: checks the equation via pairing**

```console
# 26 * G2 (uncompressed)
$ TWENTY_SIX_G2_COMPRESSED=$(cargo run --quiet -- mul --g2 --point generator --scalar "26")
$ echo "$TWENTY_SIX_G2_COMPRESSED"
0x8bb319a4550c981ee89e3c7e6dcc434283454847792807940f72fd2dbf3625b092e0a0c03e581fd9bd9cf74f95ccef150029ea93c2f1eb48b195815571ea0148198ff1b19462618cab08d037646b592ecab5a66b4bc660ffd02d1b996ca377da

$ TWENTY_SIX_G2=$(echo "$TWENTY_SIX_G2_COMPRESSED" | cargo run --quiet -- uncompress --g2)
$ echo "$TWENTY_SIX_G2"
0x0bb319a4550c981ee89e3c7e6dcc434283454847792807940f72fd2dbf3625b092e0a0c03e581fd9bd9cf74f95ccef150029ea93c2f1eb48b195815571ea0148198ff1b19462618cab08d037646b592ecab5a66b4bc660ffd02d1b996ca377da05d04aa0b644faae17d4c76a14aa680c69fdfc6b59fee3ef45641f566165fced60cbbda4ca096e132bb6f58ab45166860abb072b8d9011e81c9f5b23ba86fdb6399c878aa4eadee45fb2486afe594dffc53be643598a23e5428894a36f5ac3ce

# e(X, Y)
$ echo "$X" | cargo run --quiet -- pairing --g2 "$Y"
0x0390df3dd3d5a63d5c7c2f911b665b134df8eb3ada0181d15aec93e1dd2e783cf47d0f47eeb642c68a566e9d00b30817a879e82adb993a1efb41c4a807c1c707762b102ee490de8ab6a32211c029f019ea8e743edf34e61b0c8ecd6df6566300ed58a2c2f204178bee12aeba33f89ff40d3408d9f485caa6b403b5759a42f1884c45b71433f491d98d2196e02f667716aefb3dfab74dd28a32d8003a8c471a12805b5fbe39481259e4f181c3af1a924319551bbe9758a9a3dbfa01fa5886fb129cf1fd13a2c970e6abe724cac7177e77b0ae2f5c4644192e446b0065da5e9a3f5dd9807783537d49497667225492b00dbf18211d38a9078f6872d9598852b3b28758d34c21782620e823cea6a50be9926206e42060665d6d03b3920cf2216705738d99f55d6611edc37d2722af1c5668b393ee09a8b84a74fc88c513744ece6ad7e4f67bc26b8d5f02e9266f5a0915182626cdc8649c3ddb029a30f67db391f143b17cb4eddae49f45b98e5a2659350dca820001b488d0c34f186cdf9d832a0bfc6090c4545df018615935bd3427b9dcdcd6abb214ce0f2a0ef4a4f029007bd5af8f2409f0683c64dc1c1f49b16bc50dea411b28e2cb0615ebc532efbbe28e8e699c3850fd31d25f0ca8ad43c90b22976556cd4303f638244bbc20ab48a3960460205ce3c61d7266c12bcdaf1505e0f162d0a0777efe391c0c0c8ceb3cb4a3fcdc9a2278ec3015ca84f7a759ade85819a8b7d201b7a4c88692814ec034b369e34550ed450498c7434152b633cd22e06ddba10f0add047fa3a3f99112f7c22417

# e(G1, 26 * G2)
$ echo "$G1_UNCOMPRESSED" | cargo run --quiet -- pairing --g2 "$TWENTY_SIX_G2"
0x0390df3dd3d5a63d5c7c2f911b665b134df8eb3ada0181d15aec93e1dd2e783cf47d0f47eeb642c68a566e9d00b30817a879e82adb993a1efb41c4a807c1c707762b102ee490de8ab6a32211c029f019ea8e743edf34e61b0c8ecd6df6566300ed58a2c2f204178bee12aeba33f89ff40d3408d9f485caa6b403b5759a42f1884c45b71433f491d98d2196e02f667716aefb3dfab74dd28a32d8003a8c471a12805b5fbe39481259e4f181c3af1a924319551bbe9758a9a3dbfa01fa5886fb129cf1fd13a2c970e6abe724cac7177e77b0ae2f5c4644192e446b0065da5e9a3f5dd9807783537d49497667225492b00dbf18211d38a9078f6872d9598852b3b28758d34c21782620e823cea6a50be9926206e42060665d6d03b3920cf2216705738d99f55d6611edc37d2722af1c5668b393ee09a8b84a74fc88c513744ece6ad7e4f67bc26b8d5f02e9266f5a0915182626cdc8649c3ddb029a30f67db391f143b17cb4eddae49f45b98e5a2659350dca820001b488d0c34f186cdf9d832a0bfc6090c4545df018615935bd3427b9dcdcd6abb214ce0f2a0ef4a4f029007bd5af8f2409f0683c64dc1c1f49b16bc50dea411b28e2cb0615ebc532efbbe28e8e699c3850fd31d25f0ca8ad43c90b22976556cd4303f638244bbc20ab48a3960460205ce3c61d7266c12bcdaf1505e0f162d0a0777efe391c0c0c8ceb3cb4a3fcdc9a2278ec3015ca84f7a759ade85819a8b7d201b7a4c88692814ec034b369e34550ed450498c7434152b633cd22e06ddba10f0add047fa3a3f99112f7c22417
```

Both pairing outputs are identical, confirming that `x × y = 26` holds — without the verifier ever learning `x = 13` or `y = 2`.

**Reverse assignment: X in G2, y in G1**

The assignment of values to groups is flexible. The prover could instead send `X = 13·G2` and `Y = 2·G1`. The verifier checks `e(Y, X) = e(2·G1, 13·G2)` against `e(G1, 26·G2)` — the pairing output is identical because `e(2·G1, 13·G2) = e(13·G1, 2·G2)`:

```console
# Prover: X = 13 * G2 (uncompressed)
$ X_G2_COMPRESSED=$(cargo run --quiet -- mul --g2 --point generator --scalar "13")
$ echo "$X_G2_COMPRESSED"
0x8bf78a97086750eb166986ed8e428ca1d23ae3bbf8b2ee67451d7dd84445311e8bc8ab558b0bc008199f577195fc39b7152110e866f1a6e8c5348f6e005dbd93de671b7d0fbfa04d6614bcdd27a3cb2a70f0deacb3608ba95226268481a0be7c

$ X_G2=$(echo "$X_G2_COMPRESSED" | cargo run --quiet -- uncompress --g2)
$ echo "$X_G2"
0x0bf78a97086750eb166986ed8e428ca1d23ae3bbf8b2ee67451d7dd84445311e8bc8ab558b0bc008199f577195fc39b7152110e866f1a6e8c5348f6e005dbd93de671b7d0fbfa04d6614bcdd27a3cb2a70f0deacb3608ba95226268481a0be7c0a298f69fd652551e12219252baacab101768fc6651309450e49c7d3bb52b7547f218d12de64961aa7f059025b8e0cb50845be51ad0d708657bfb0da8eec64cd7779c50d90b59a3ac6a2045cad0561d654af9a84dd105cea5409d2adf286b561

# Prover: Y = 2 * G1 (uncompressed)
$ Y_G1_COMPRESSED=$(cargo run --quiet -- mul --g1 --point generator --scalar "2")
$ echo "$Y_G1_COMPRESSED"
0xa572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e

$ Y_G1=$(echo "$Y_G1_COMPRESSED" | cargo run --quiet -- uncompress --g1)
$ echo "$Y_G1"
0x0572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e166a9d8cabc673a322fda673779d8e3822ba3ecb8670e461f73bb9021d5fd76a4c56d9d4cd16bd1bba86881979749d28

# Verifier: e(Y, X) — note Y (G1) comes first, then X (G2)
$ echo "$Y_G1" | cargo run --quiet -- pairing --g2 "$X_G2"
0x0390df3dd3d5a63d5c7c2f911b665b134df8eb3ada0181d15aec93e1dd2e783cf47d0f47eeb642c68a566e9d00b30817a879e82adb993a1efb41c4a807c1c707762b102ee490de8ab6a32211c029f019ea8e743edf34e61b0c8ecd6df6566300ed58a2c2f204178bee12aeba33f89ff40d3408d9f485caa6b403b5759a42f1884c45b71433f491d98d2196e02f667716aefb3dfab74dd28a32d8003a8c471a12805b5fbe39481259e4f181c3af1a924319551bbe9758a9a3dbfa01fa5886fb129cf1fd13a2c970e6abe724cac7177e77b0ae2f5c4644192e446b0065da5e9a3f5dd9807783537d49497667225492b00dbf18211d38a9078f6872d9598852b3b28758d34c21782620e823cea6a50be9926206e42060665d6d03b3920cf2216705738d99f55d6611edc37d2722af1c5668b393ee09a8b84a74fc88c513744ece6ad7e4f67bc26b8d5f02e9266f5a0915182626cdc8649c3ddb029a30f67db391f143b17cb4eddae49f45b98e5a2659350dca820001b488d0c34f186cdf9d832a0bfc6090c4545df018615935bd3427b9dcdcd6abb214ce0f2a0ef4a4f029007bd5af8f2409f0683c64dc1c1f49b16bc50dea411b28e2cb0615ebc532efbbe28e8e699c3850fd31d25f0ca8ad43c90b22976556cd4303f638244bbc20ab48a3960460205ce3c61d7266c12bcdaf1505e0f162d0a0777efe391c0c0c8ceb3cb4a3fcdc9a2278ec3015ca84f7a759ade85819a8b7d201b7a4c88692814ec034b369e34550ed450498c7434152b633cd22e06ddba10f0add047fa3a3f99112f7c22417

# Verifier: e(G1, 26 * G2) — same reference check
$ echo "$G1_UNCOMPRESSED" | cargo run --quiet -- pairing --g2 "$TWENTY_SIX_G2"
0x0390df3dd3d5a63d5c7c2f911b665b134df8eb3ada0181d15aec93e1dd2e783cf47d0f47eeb642c68a566e9d00b30817a879e82adb993a1efb41c4a807c1c707762b102ee490de8ab6a32211c029f019ea8e743edf34e61b0c8ecd6df6566300ed58a2c2f204178bee12aeba33f89ff40d3408d9f485caa6b403b5759a42f1884c45b71433f491d98d2196e02f667716aefb3dfab74dd28a32d8003a8c471a12805b5fbe39481259e4f181c3af1a924319551bbe9758a9a3dbfa01fa5886fb129cf1fd13a2c970e6abe724cac7177e77b0ae2f5c4644192e446b0065da5e9a3f5dd9807783537d49497667225492b00dbf18211d38a9078f6872d9598852b3b28758d34c21782620e823cea6a50be9926206e42060665d6d03b3920cf2216705738d99f55d6611edc37d2722af1c5668b393ee09a8b84a74fc88c513744ece6ad7e4f67bc26b8d5f02e9266f5a0915182626cdc8649c3ddb029a30f67db391f143b17cb4eddae49f45b98e5a2659350dca820001b488d0c34f186cdf9d832a0bfc6090c4545df018615935bd3427b9dcdcd6abb214ce0f2a0ef4a4f029007bd5af8f2409f0683c64dc1c1f49b16bc50dea411b28e2cb0615ebc532efbbe28e8e699c3850fd31d25f0ca8ad43c90b22976556cd4303f638244bbc20ab48a3960460205ce3c61d7266c12bcdaf1505e0f162d0a0777efe391c0c0c8ceb3cb4a3fcdc9a2278ec3015ca84f7a759ade85819a8b7d201b7a4c88692814ec034b369e34550ed450498c7434152b633cd22e06ddba10f0add047fa3a3f99112f7c22417
```

The output matches the original case — the verifier accepts either assignment, since `e(13·G1, 2·G2) = e(2·G1, 13·G2)`.

This technique, known as a **quadratic arithmetic program**, is the foundation of zk-SNARKs and other advanced zero-knowledge protocols built on BLS12-381.
```
