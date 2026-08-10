import json
import nacl.signing
import nacl.encoding
from nacl.bindings import crypto_sign

# Generate a test Ed25519 keypair
sk = nacl.signing.SigningKey.generate()
vk = sk.verify_key

# Message to sign (must be 32 bytes for the hardcoded n=256 circuit)
msg = b'hello world! this is 32 bytes ok'

# Sign the message
signed = sk.sign(msg)

# Ed25519 signature components:
# - R: first 32 bytes (compressed point)
# - S: last 32 bytes (scalar)
R_bytes = signed.signature[:32]
S_bytes = signed.signature[32:]
A_bytes = bytes(vk)

# Convert bytes to bit arrays (little-endian bit order as used in the circuit)
def bytes_to_bits_le(data):
    bits = []
    for byte in data:
        for i in range(8):
            bits.append((byte >> i) & 1)
    return bits

A_bits = bytes_to_bits_le(A_bytes)
R_bits = bytes_to_bits_le(R_bytes)
S_bits = bytes_to_bits_le(S_bytes)[:255]  # Circuit expects 255 bits, not 256
msg_bits = bytes_to_bits_le(msg)

# Decompress points to get extended coordinates [X, Y, Z, T]
# We need to do this manually since nacl doesn't expose it

p = 2**255 - 19
d = -121665 * pow(121666, p-2, p) % p  # Ed25519 curve constant d

def decompress_point(y_bytes):
    """Decompress Ed25519 point from 32 bytes to extended coordinates [X, Y, Z, T]"""
    # Parse y coordinate (little-endian, top bit is sign of x)
    y_int = int.from_bytes(y_bytes, 'little')
    sign_x = y_int >> 255
    y_int &= (1 << 255) - 1
    
    # Compute x from curve equation: x^2 = (y^2 - 1) / (d*y^2 + 1)
    y2 = (y_int * y_int) % p
    u = (y2 - 1) % p
    v = (d * y2 + 1) % p
    v_inv = pow(v, p-2, p)
    x2 = (u * v_inv) % p
    
    # Square root of x^2
    x = pow(x2, (p+3)//8, p)
    if (x * x) % p != x2:
        x = (x * pow(2, (p-1)//4, p)) % p
    
    if x & 1 != sign_x:
        x = (-x) % p
    
    # Extended coordinates: X, Y, Z, T
    return [x, y_int, 1, (x * y_int) % p]

def to_chunks(val, bits=85, n=3):
    """Split integer into n chunks of bits bits each"""
    chunks = []
    for i in range(n):
        chunk = (val >> (i * bits)) & ((1 << bits) - 1)
        chunks.append(chunk)
    return chunks

PointA = decompress_point(A_bytes)
PointR = decompress_point(R_bytes)

# Convert to chunked form
PointA_chunks = [to_chunks(c) for c in PointA]
PointR_chunks = [to_chunks(c) for c in PointR]

# Build input JSON
circuit_input = {
    "msg": [str(b) for b in msg_bits],
    "A": [str(b) for b in A_bits],
    "R8": [str(b) for b in R_bits],
    "S": [str(b) for b in S_bits],
    "PointA": [[str(c) for c in row] for row in PointA_chunks],
    "PointR": [[str(c) for c in row] for row in PointR_chunks],
}

with open('test_verify_input.json', 'w') as f:
    json.dump(circuit_input, f, indent=2)

print("Generated test_verify_input.json")
print(f"Message length: {len(msg_bits)} bits")
print(f"A bits (first 10): {A_bits[:10]}")
print(f"PointA chunks: {PointA_chunks}")
print(f"PointR chunks: {PointR_chunks}")

# Verify the signature with nacl
try:
    vk.verify(msg, signed.signature)
    print("Signature is VALID (verified by nacl)")
except Exception as e:
    print(f"Signature verification failed: {e}")
