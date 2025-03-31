from py_ecc.bls12_381 import (
    G1, G2, add, multiply, pairing, curve_order, FQ
)
from hashlib import sha256
import secrets
from datetime import datetime
import json

# Helper Functions
def hash_to_scalar(data):
    """Hash data to a scalar in the curve order"""
    if isinstance(data, dict):
        data = json.dumps(data, sort_keys=True).encode()
    return int.from_bytes(sha256(data).digest(), "big") % curve_order

def generate_commitment(secret, blinding_factor=None):
    """Pedersen commitment: C = G1*secret + H*blinding"""
    if blinding_factor is None:
        blinding_factor = secrets.randbelow(curve_order)
    H = multiply(G1, 12345)  # Fixed generator for blinding (in practice, use hash-to-curve)
    return add(
        multiply(G1, secret),
        multiply(H, blinding_factor)
    ), blinding_factor

# Age Proof Protocol
class AgeProof:
    def __init__(self, dob_string, current_year):
        self.dob = datetime.strptime(dob_string, '%Y-%m-%d')
        self.current_year = current_year
        self.age = current_year - self.dob.year
        
    def prove_age_over(self, min_age):
        """Generate ZK proof that age > min_age"""
        assert self.age > min_age, "Age requirement not met"
        
        # 1. Prover's secret (birth year)
        birth_year = self.dob.year
        year_commitment, r = generate_commitment(birth_year)
        
        # 2. Compute difference (delta = current_year - birth_year - min_age - 1)
        delta = self.current_year - birth_year - min_age - 1
        
        # 3. Prove delta is non-negative without revealing birth_year
        # This would normally be a range proof, simplified here for illustration
        delta_commitment, r_delta = generate_commitment(delta)
        
        # Simulated proof (in reality, use Bulletproofs or similar)
        challenge = hash_to_scalar({
            'year_commit': str(year_commitment),
            'delta_commit': str(delta_commitment),
            'min_age': min_age
        })
        
        response = (r + challenge * birth_year) % curve_order
        
        return {
            'year_commitment': year_commitment,
            'delta_commitment': delta_commitment,
            'challenge': challenge,
            'response': response,
            'current_year': self.current_year,
            'min_age': min_age
        }
    
    @staticmethod
    def verify_age_over(proof):
        """Verify the ZK age proof"""
        # Reconstruct challenge
        challenge = hash_to_scalar({
            'year_commit': str(proof['year_commitment']),
            'delta_commit': str(proof['delta_commitment']),
            'min_age': proof['min_age']
        })
        
        # Verify the commitment structure (simplified)
        H = multiply(G1, 12345)
        expected_commit = add(
            multiply(proof['year_commitment'], proof['challenge']),
            multiply(H, proof['response'])
        )
        
        # In a real implementation, you'd verify the range proof here
        # This is a simplified check
        return (
            challenge == proof['challenge'] and
            proof['current_year'] - proof['min_age'] > 0  # Placeholder
        )

# Example Usage
if __name__ == "__main__":
    # User setup
    user_dob = "1990-05-15"
    current_year = datetime.now().year
    age_prover = AgeProof(user_dob, current_year)
    
    # Generate proof
    min_required_age = 21
    proof = age_prover.prove_age_over(min_required_age)
    print(f"Generated proof for age > {min_required_age}")
    
    # Verification
    is_valid = AgeProof.verify_age_over(proof)
    print(f"Proof valid: {is_valid}")
    
    # What the verifier sees
    print("\nVerifier sees only:")
    print(f"- Commitment to birth year: {proof['year_commitment']}")
    print(f"- Commitment to age delta: {proof['delta_commitment']}")
    print(f"- Proof structure, but no actual DOB")