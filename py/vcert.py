from py_ecc.bls12_381 import (
    G1, G2, add, multiply, pairing, curve_order, FQ, FQ2
)
from hashlib import sha256
import secrets
import json
from datetime import datetime

def hash_to_scalar(data):
    """Hash data to a scalar in the curve order"""
    if isinstance(data, dict):
        data = json.dumps(data, sort_keys=True).encode()
    return int.from_bytes(sha256(data).digest(), "big") % curve_order

def generate_issuer_keys():
    """Generate issuer's key pair"""
    sk = secrets.randbelow(curve_order)
    pk = multiply(G2, sk)  # Public key in G2
    return sk, pk

def create_certificate(issuer_sk, user_data):
    """
    Create a verifiable certificate for user data
    user_data should contain 'name' and 'dob' fields
    """
    # Convert data to structured format
    assert 'name' in user_data and 'dob' in user_data
    data_hash = hash_to_scalar(user_data)
    
    # Create signature (certificate)
    signature = multiply(G1, (issuer_sk * data_hash) % curve_order)
    
    return {
        'user_data': user_data,
        'signature': signature,
        'issuer_pk': multiply(G2, issuer_sk)  # In real use, would be the actual issuer pk
    }

def verify_certificate(certificate):
    """Verify the certificate's authenticity"""
    # Extract components
    user_data = certificate['user_data']
    signature = certificate['signature']
    issuer_pk = certificate['issuer_pk']
    
    # Recompute hash
    data_hash = hash_to_scalar(user_data)
    g1_data = multiply(G1, data_hash)
    
    # Verify pairing: e(signature, G2) == e(g1_data, issuer_pk)
    pairing1 = pairing(G2, signature)
    pairing2 = pairing(issuer_pk, g1_data)
    
    return pairing1 == pairing2

# Example Usage
if __name__ == "__main__":
    # 1. Issuer Setup
    issuer_sk, issuer_pk = generate_issuer_keys()
    
    # 2. User data
    user_data = {
        'name': 'Alice Smith',
        'dob': '1990-05-15'  # YYYY-MM-DD format
    }
    
    # 3. Create certificate
    cert = create_certificate(issuer_sk, user_data)
    print("Certificate created for:", user_data['name'])
    
    # 4. Verify certificate
    is_valid = verify_certificate(cert)
    print(f"Certificate valid: {is_valid}")
    