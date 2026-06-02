# KDF (Key Derivation Function)

A key derivation function generates DETERMINISTICALLY  a derived key from a base key and
additional parameters. Its goal is to take some source of initial
keying material and derive from it one or more cryptographically strong secret keys.
In a password-based key derivation function, the
base key is a password, and the additional parameters are an iteration count and a salt value.
The base key could also be a private key.

There are many standardsfocusing on KDF, namely [HKDF](https://datatracker.ietf.org/doc/html/rfc5869) and
[PBKDF2](https://datatracker.ietf.org/doc/html/rfc8018).

# PBKDF2

The library provides aiken-based implementation of PBKDF2 scheme as outlined [here](https://datatracker.ietf.org/doc/html/rfc8018#page-11).
