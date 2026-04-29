### Commands

### generate-seed

Generate a 32-byte random hex-encoded seed.

```console
$ cargo run --quiet -- generate-seed ; echo
9fb87a5bacb1c54b2e770d6d091da4c04797c1cd760d765ddb026ec3d703d5b2
```

### hkdf

Derive a 32-byte PrivateKey from a seed using HKDF-SHA256.

From the seed above:

```console
$ echo "9fb87a5bacb1c54b2e770d6d091da4c04797c1cd760d765ddb026ec3d703d5b2" | cargo run --quiet -- hkdf
7be162d67564e3b4c09655baaabecc3725748133e33ab971e565737f189f3f43
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

Convert a 32-byte private key to its BLS12-381 scalar representation (decimal output).

The command validates that:
- The input is exactly 32 bytes (64 hex characters)
- The scalar is within the valid curve order range

From the private key derived above:

```console
$ echo "7be162d67564e3b4c09655baaabecc3725748133e33ab971e565737f189f3f43" | cargo run --quiet -- scalar
30417370258289878983951032069403093024210548576862328133794263911723866186107
```

**From file:**
```console
$ cargo run --quiet -- scalar --file private_key.hex
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
$ echo "7be162d67564e3b4c09655baaabecc3725748133e33ab971e565737f189f3f43" | cargo run --quiet -- pk
ab21260f2c9d1fb30a46aec117e8c4a0f65f9a8f5b177361c3680da3097eb448b3eb6d0960776f73f4e5bb41d1256371
```

**From file:**
```console
$ cargo run --quiet -- pk --file private_key.hex
```

**From stdin:**
```console
$ cargo run --quiet -- pk < private_key.hex
```
