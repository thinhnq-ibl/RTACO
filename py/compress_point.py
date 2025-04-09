from py_ecc.optimized_bls12_381 import (
    G1,
    multiply,
)
from py_ecc.bls.point_compression import (
    compress_G1,
    decompress_G1,
)
import hashlib
import os
from py_ecc.bls.hash import (
    i2osp,
    os2ip
)

def generate_private_key():
    # Generate a 32-byte random scalar (mod curve order)
    return int.from_bytes(os.urandom(32), 'big') % (2**255 - 19)  # curve order can be improved

def get_public_key(privkey):
    # G1 * privkey = pubkey
    return multiply(G1, privkey)

def compress_pubkey(pubkey):
    return compress_G1(pubkey)

def decompress_pubkey(data):
    return decompress_G1(data)

def main():
    # print("Generating private key...")
    # privkey = generate_private_key()
    # print(f"Private Key: {hex(privkey)}")

    # print("\nGenerating public key (G1)...")
    # pubkey = get_public_key(privkey)
    # print(f"Public Key (Jacobian): {pubkey}")
    # print(f"Public Key (Affine): {normalize(pubkey)}")

    # print("\nCompressing public key...")
    # compressed = compress_pubkey(pubkey)
    # print(f"Compressed (hex): {i2osp(compressed, 48).hex()}")

    # print("\nDecompressing...")
    # hex_String = "82cbde4e4fc6a56b6f84f2ceabb191ed7d4402835f8caa1e166554e7d7a925fe2cab59f113b78c91a4b37001d2a9c75f"
    # decompressed = decompress_pubkey(os2ip(bytes.fromhex(hex_String)))
    # print(f"Decompressed (Jacobian): {decompressed}")
    # print(f"Decompressed (Affine): {normalize(decompressed)}")

    # print("\n✅ Do they match?")
    # print("Match:", normalize(pubkey) == normalize(decompressed))

    prv = "6284b61a07c6bd3e632beb6294dfc780ad04489c8c31b73b0aef73608f3d1231"
    pubkey = get_public_key(int.from_bytes(bytes.fromhex(prv), 'big'))
    print(f"Private Key: {prv}")
    print(f"Public Key: {pubkey}") 
    print(f"Compressed (hex): {i2osp(compress_pubkey(pubkey), 48).hex()}")
    pubkey_compress_hex_String = "82cbde4e4fc6a56b6f84f2ceabb191ed7d4402835f8caa1e166554e7d7a925fe2cab59f113b78c91a4b37001d2a9c75f"
    assert i2osp(compress_pubkey(pubkey), 48).hex() == pubkey_compress_hex_String


if __name__ == "__main__":
    main()
