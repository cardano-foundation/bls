### Commands

### generate-seed

Generate a 32-byte random hex-encoded seed.

```console
$ cargo run --quiet -- generate-seed ; echo
bf410498bcb54308b2f9483a488430610fb40e4dd7d84baa1bbb35174231b0e0
```

### hkdf

Derive a 32-byte PrivateKey from a seed.

**From stdin:**
```console
$ cargo run --quiet -- hkdf < seed.hex
```

**From file:**
```console
$ cargo run --quiet -- hkdf --file seed.hex
```

If the seed is shorter than 32 bytes, it repeats to fill 32 bytes.

