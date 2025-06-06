from py_ecc.bls12_381 import (
    G1, G2, add, multiply, pairing, curve_order, 
    FQ, FQ2, FQ12
)
from hashlib import sha256
import secrets

def hash_to_G1(msg):
    """Simple hash-to-curve (for demo purposes - use proper hash_to_curve in production)"""
    h = sha256(msg).digest()
    x = int.from_bytes(h, 'big') % curve_order
    return multiply(G1, x)

def generate_keypair():
    """Generate private/public key pair"""
    sk = secrets.randbelow(curve_order)
    pk = multiply(G2, sk)
    return sk, pk

def sign(sk, msg):
    """Create BLS signature"""
    H = hash_to_G1(msg)
    return multiply(H, sk)

def verify(pk, msg, sig):
    """Verify single BLS signature"""
    H = hash_to_G1(msg)
    # e(sig, G2) == e(H, pk)
    pairing1 = pairing(G2, sig)
    pairing2 = pairing(pk, H)
    return pairing1 == pairing2

def aggregate_signatures(signatures):
    """Combine multiple signatures into one"""
    agg_sig = None
    for sig in signatures:
        if agg_sig is None:
            agg_sig = sig
        else:
            agg_sig = add(agg_sig, sig)
    return agg_sig

def aggregate_verify(pks, msgs, agg_sig):
    """Verify an aggregate signature"""
    if len(pks) != len(msgs):
        return False
    
    # Compute product of pairings: prod(e(H_i, pk_i))
    product_pairing = FQ12.one()
    for pk, msg in zip(pks, msgs):
        H = hash_to_G1(msg)
        product_pairing = product_pairing * pairing(pk, H)
    
    # Compute pairing for aggregate sig: e(agg_sig, G2)
    sig_pairing = pairing(G2, agg_sig)
    
    # Final exponentiation and comparison
    return sig_pairing == product_pairing

# Example Usage
if __name__ == "__main__":
    # Generate 3 key pairs
    sk1, pk1 = generate_keypair()
    sk2, pk2 = generate_keypair()
    sk3, pk3 = generate_keypair()

    # Different messages
    msg1 = b"Transaction 1"
    msg2 = b"Transaction 2"
    msg3 = b"Transaction 3"

    # Create individual signatures
    sig1 = sign(sk1, msg1)
    sig2 = sign(sk2, msg2)
    sig3 = sign(sk3, msg3)

    # Verify individual signatures
    print(f"Sig1 valid: {verify(pk1, msg1, sig1)}")
    print(f"Sig2 valid: {verify(pk2, msg2, sig2)}")
    print(f"Sig3 valid: {verify(pk3, msg3, sig3)}")

    # Aggregate signatures
    agg_sig = aggregate_signatures([sig1, sig2, sig3])
    print("\nAggregate signature:", agg_sig)

    # Verify aggregate signature
    is_valid = aggregate_verify([pk1, pk2, pk3], [msg1, msg2, msg3], agg_sig)
    print(f"\nAggregate signature valid: {is_valid}")

    # Test with wrong messages (should fail)
    is_valid_wrong = aggregate_verify([pk1, pk2, pk3], [msg1, b"Wrong", msg3], agg_sig)
    print(f"Aggregate signature with wrong messages: {is_valid_wrong}")