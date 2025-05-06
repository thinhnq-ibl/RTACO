from py_ecc.optimized_bls12_381 import (
    G1,
    multiply,

)
from py_ecc.bls.point_compression import (
    compress_G1,
    decompress_G1,
    compress_G2,
    decompress_G2,
    G1Uncompressed
)

from py_ecc.fields import (
    optimized_bls12_381_FQ as FQO,
    optimized_bls12_381_FQ2 as FQO2,
    optimized_bls12_381_FQ12 as FQO12,
    optimized_bls12_381_FQP as FQPO,
)

import hashlib
import os
from py_ecc.bls.hash import (
    i2osp,
    os2ip
)

from py_ecc.bls.typing import (G2Compressed)

def generate_private_key():
    # Generate a 32-byte random scalar (mod curve order)
    return int.from_bytes(os.urandom(32), 'big') % (2**255 - 19)  # curve order can be improved

def get_public_key(privkey):
    # G1 * privkey = pubkey
    print(f"privkey: {privkey}")
    print(f"G1: {G1}")
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
    # pubkey = get_public_key(int.from_bytes(bytes.fromhex(prv), 'big'))
    pubkey: G1Uncompressed = (FQO(3269738153309571450714394264030262776973204406823995144230683521590333770248416559499546637727379823385026562495637),
                              FQO( 2683600539795682083209673554465384968512937233268668186083001842704041096992949667318245869852157686156313520412367), 
                              FQO(1))
    print(f"Private Key: {prv}")
    print(f"Public Key: {pubkey}") 
    print(f"Compressed (hex): {i2osp(compress_pubkey(pubkey), 48).hex()}")
    pubkey_compress_hex_string = "82cbde4e4fc6a56b6f84f2ceabb191ed7d4402835f8caa1e166554e7d7a925fe2cab59f113b78c91a4b37001d2a9c75f"
    assert i2osp(compress_pubkey(pubkey), 48).hex() == pubkey_compress_hex_string

    # G2 point
    hash = bytes.fromhex("b8ee5db274e4ed884d6acae616b1c292004bb3df5c150e7eee66d6aed86ce3481300cdfe037651d9e01af95f539bf63a13d14cbc4ff1c45149ece6777e6c5b2860c0ec14253b9667200ea5bb6c2d11bf1315c552da7a7d60092d7010da158a2f")
    p = G2Compressed((os2ip(hash[:48]), os2ip(hash[48:])))
    hashG2 = decompress_G2(p)
    # G2 signature
    sign = multiply(hashG2, int.from_bytes(bytes.fromhex(prv), 'big'))
    signComp = compress_G2(sign)
    sign_compress_hex_string = "b558aab6dd33d777973a19fb34c3a1c636315a039a0e9ea7da4f78fe5d4470a0b4ec3d2b3324b81e5e759875c224c8ec0e1ce698faa40426165f799cb358d965b8e8dc82ee01f702008e68a0309a8261bb5e348f349521b26eed6961c22de869"
    print (f"Signature: {i2osp(signComp[0], 48).hex() + i2osp(signComp[1], 48).hex()}")
    assert i2osp(signComp[0], 48).hex() + i2osp(signComp[1], 48).hex() == sign_compress_hex_string
if __name__ == "__main__":
    main()
