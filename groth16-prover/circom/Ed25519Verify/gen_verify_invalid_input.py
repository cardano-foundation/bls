import json
import nacl.signing
import nacl.encoding
from nacl.bindings import crypto_sign

# Generate a test Ed25519 keypair
sk = nacl.signing.SigningKey.generate()
vk = sk.verify_key

# Message to sign
msg = b'hello world! this is 32 bytes ok'

# Sign the message
signed = sk.sign(msg)

# Now modify the signature to make it INVALID
# Change the last byte of S
bad_signature = bytearray(signed.signature)
bad_signature[-1] ^= 0xFF  # Flip all bits in last byte

# Extract components
R_bytes = bytes(bad_signature[:32])
S_bytes = bytes(bad_signature[32:])
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
S_bits = bytes_to_bits_le(S_bytes)[:255]
msg_bits = bytes_to_bits_le(msg)

# Decompress points
p = 2**255 - 19
d = -121665 * pow(121666, p-2, p) % p

def decompress_point(y_bytes):
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
    chunks = []
    for i in range(n):
        chunk = (val >> (i * bits)) & ((1 << bits) - 1)
        chunks.append(chunk)
    return chunks

PointA = decompress_point(A_bytes)
PointR = decompress_point(R_bytes)

PointA_chunks = [to_chunks(c) for c in PointA]
PointR_chunks = [to_chunks(c) for c in PointR]

circuit_input = {
    "msg": [str(b) for b in msg_bits],
    "A": [str(b) for b in A_bits],
    "R8": [str(b) for b in R_bits],
    "S": [str(b) for b in S_bits],
    "PointA": [[str(c) for c in row] for row in PointA_chunks],
    "PointR": [[str(c) for c in row] for row in PointR_chunks],
}

with open('test_verify_invalid_input.json', 'w') as f:
    json.dump(circuit_input, f, indent=2)

print("Generated test_verify_invalid_input.json with INVALID signature")

# Verify the signature with nacl (should fail)
try:
    vk.verify(msg, bytes(bad_signature))
    print("ERROR: nacl accepted the bad signature!")
except Exception as e:
    print(f"nacl correctly rejected: {type(e).__name__}")
