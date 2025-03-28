from py_ecc.bls12_381 import (
    G1, G2, add, multiply, neg, pairing, curve_order, FQ
)
from hashlib import sha256
import secrets

def to_binary256(data):
    """Convert input to 256-bit binary representation"""
    if isinstance(data, (int, str)):
        data = str(data).encode()
    return sha256(data).digest()

def hash_to_scalar(msg):
    """Hash a message to a scalar in the curve order"""
    return int.from_bytes(to_binary256(msg), "big") % curve_order

def generate_keypair():
    """Generate signer's key pair"""
    sk = secrets.randbelow(curve_order)
    pk = multiply(G2, sk)  # Public key in G2
    return sk, pk

def blind_message( message):
    """User blinds the message before sending to signer"""
    # Hash the message
    h = hash_to_scalar(message)
    
    # Generate blinding factor
    r = secrets.randbelow(curve_order - 1) + 1
    
    # Compute blinded message
    blinded_msg = (h * r) % curve_order
    return blinded_msg, r

def blind_sign(sk, blinded_msg):
    """Signer creates a blind signature"""
    # Simple blind signature: s = sk * blinded_msg
    s = (sk * blinded_msg) % curve_order
    return multiply(G1, s)  # Return signature in G1

def unblind_signature(blind_sig, r):
    """User unblinds the signature"""
    # Compute r^-1 mod curve_order
    r_inv = pow(r, -1, curve_order)
    
    # Unblind the signature
    unblinded_sig = multiply(blind_sig, r_inv)
    return unblinded_sig

def verify_signature(pk, message, signature):
    """Verify the unblinded signature"""
    # Hash the message
    h = hash_to_scalar(message)
    
    # Compute required pairings
    # e(signature, g2) == e(g1^h, pk)
    g1_h = multiply(G1, h)
    pairing1 = pairing(G2, signature)
    pairing2 = pairing(pk, g1_h)
    
    # Final exponentiation and comparison
    return pairing1 == pairing2

# Example usage
if __name__ == "__main__":
    # 1. Key Generation
    sk, pk = generate_keypair()
    print("Key generation complete")
    
    # 2. User prepares message
    message = b"Hello, blind signature world!"
    blinded_msg, r = blind_message(message)
    print("Message blinded", blinded_msg, r) 
    
    # 3. Signer creates blind signature
    blind_sig = blind_sign(sk, blinded_msg)
    print("Blind signature created", blind_sig)
    
    # 4. User unblinds signature
    signature = unblind_signature(blind_sig, r)
    print("Signature unblinded", signature)
    
    # 5. Verify signature
    is_valid = verify_signature(pk, message, signature)
    print(f"Signature valid: {is_valid}")
    
    # Test with wrong message (should fail)
    is_valid_wrong = verify_signature(pk, b"Wrong message", signature)
    print(f"Signature valid for wrong message: {is_valid_wrong}")