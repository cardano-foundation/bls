### Commands

Run `cargo run --help` or `cargo run -- <command> --help` for detailed information about each command.

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
$ echo "7be162d67564e3b4c09655baaabecc3725748133e33ab971e565737f189f3f43" | cargo run --quiet -- pk
ab21260f2c9d1fb30a46aec117e8c4a0f65f9a8f5b177361c3680da3097eb448b3eb6d0960776f73f4e5bb41d1256371
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
$ echo "7be162d67564e3b4c09655baaabecc3725748133e33ab971e565737f189f3f43" | cargo run --quiet -- sig --msg "hello world"
a00ac57c24c5ec4db94fe1fee003f7dd15c100041cafba26ba97c0c6e18e04106c4d0dbd03ab5ba6c08ccea14a9ddc5c06d326a27134b6d150343064697bd1d9ed8883b1cdc60fe97baf7d67da28a1e0f63f0456deb99987389183b94ef60798
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
