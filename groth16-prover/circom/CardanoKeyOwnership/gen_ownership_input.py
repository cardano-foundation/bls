import json
import nacl.signing
import nacl.encoding
import hashlib

# Generate a test Ed25519 keypair
sk = nacl.signing.SigningKey.generate()
vk = sk.verify_key

# Ed25519 public key (compressed, 32 bytes)
A_bytes = bytes(vk)

# Ed25519 key derivation: the scalar 'a' is derived from SHA-512(private_key)
# with clamping (clear bottom 3 bits, clear top bit, set second-top bit).
# This is the scalar used for public key generation: P = [a]·G
sk_bytes = bytes(sk)
h = hashlib.sha512(sk_bytes).digest()
a_bytes = bytearray(h[:32])
a_bytes[0] &= 0xF8    # clear bottom 3 bits
a_bytes[31] &= 0x7F   # clear top bit
a_bytes[31] |= 0x40   # set second-top bit

# Convert bytes to bit arrays (little-endian bit order as used in the circuit)
def bytes_to_bits_le(data):
    bits = []
    for byte in data:
        for i in range(8):
            bits.append((byte >> i) & 1)
    return bits

A_bits = bytes_to_bits_le(A_bytes)
sk_bits = bytes_to_bits_le(a_bytes)[:255]  # Circuit expects 255 bits

# Decompress public key to get extended coordinates [X, Y, Z, T]
p = 2**255 - 19
d = -121665 * pow(121666, p-2, p) % p  # Ed25519 curve constant d

def decompress_point(y_bytes):
    """Decompress Ed25519 point from 32 bytes to extended coordinates [X, Y, Z, T]"""
    y_int = int.from_bytes(y_bytes, 'little')
    sign_x = y_int >> 255
    y_int &= (1 << 255) - 1
    
    y2 = (y_int * y_int) % p
    u = (y2 - 1) % p
    v = (d * y2 + 1) % p
    v_inv = pow(v, p-2, p)
    x2 = (u * v_inv) % p
    
    x = pow(x2, (p+3)//8, p)
    if (x * x) % p != x2:
        x = (x * pow(2, (p-1)//4, p)) % p
    
    if x & 1 != sign_x:
        x = (-x) % p
    
    return [x, y_int, 1, (x * y_int) % p]

def to_chunks(val, bits=85, n=3):
    """Split integer into n chunks of bits bits each"""
    chunks = []
    for i in range(n):
        chunk = (val >> (i * bits)) & ((1 << bits) - 1)
        chunks.append(chunk)
    return chunks

PointA = decompress_point(A_bytes)
PointA_chunks = [to_chunks(c) for c in PointA]

# Build input JSON
circuit_input = {
    "A": [str(b) for b in A_bits],
    "sk": [str(b) for b in sk_bits],
    "PointA": [[str(c) for c in row] for row in PointA_chunks],
}

with open('test_ownership_input.json', 'w') as f:
    json.dump(circuit_input, f, indent=2)

print("Generated test_ownership_input.json")
print(f"Public key A bits (first 10): {A_bits[:10]}")
print(f"PointA chunks: {PointA_chunks}")
print(f"Scalar sk bits (first 10): {sk_bits[:10]}")

# Sanity check: verify the scalar is correctly derived
print(f"Scalar a (hex): {a_bytes.hex()}")
print(f"Public key A (hex): {A_bytes.hex()}")
print("Input generated successfully for Cardano Ed25519 ownership circuit.")
print("Note: sk is the clamped Ed25519 scalar derived from the raw private key via SHA-512.")
