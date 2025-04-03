from py_ecc.bls12_381 import (
    G1, G2, add, multiply, pairing, curve_order, 
    FQ, FQ2, FQ12
)
import math

def decompress_g1(compressed_point: bytes) -> tuple:
    """
    Decompress a BLS12-381 G1 point following the standard bit flags:
    - MSB (bit 7): 1 = compressed, 0 = uncompressed
    - bit 6: 1 = point at infinity
    - bit 5: y-coordinate sign (when compressed and not infinity)
    
    Args:
        compressed_point: 48 bytes (compressed) or 96 bytes (uncompressed)
    
    Returns:
        Tuple (x, y) representing the decompressed point
    """
    if len(compressed_point) not in (48, 96):
        raise ValueError("Point must be 48 (compressed) or 96 (uncompressed) bytes")
    
    flags = compressed_point[0] if len(compressed_point) == 48 else compressed_point[48]
    is_compressed = (flags & 0b10000000) != 0
    
    # Handle uncompressed form
    if not is_compressed:
        if len(compressed_point) != 96:
            raise ValueError("Uncompressed points must be 96 bytes")
        x = int.from_bytes(compressed_point[:48], 'big')
        y = int.from_bytes(compressed_point[48:96], 'big')
        return (x, y)
    
    # Handle infinity point
    if (flags & 0b01000000):
        if any(b != 0 for b in compressed_point[:48]):
            raise ValueError("Infinity point must have all zeroes in data")
        return (None, None)  # Point at infinity
    
    # Decompress the point
    x = int.from_bytes(compressed_point[:48], 'big')
    
    # Curve equation: y² = x³ + 4
    y_squared = (pow(x, 3, curve_order) + 4) % curve_order
    y = tonelli_shanks(y_squared, curve_order)
    
    # Choose y based on the sign bit (bit 5)
    y_larger = (flags & 0b00100000) != 0
    y_is_larger = y > (-y) % curve_order
    
    if y_larger != y_is_larger:
        y = (-y) % curve_order
    
    return (x, y)

def tonelli_shanks(n, p):
    """Find r such that r^2 ≡ n mod p"""
    if n == 0:
        return 0
    if p == 2:
        return n
    if pow(n, (p-1)//2, p) != 1:
        raise ValueError("No square root exists")
    
    # p-1 = Q*2^S
    Q = p - 1
    S = 0
    while Q % 2 == 0:
        Q //= 2
        S += 1
    
    # Find z which is a quadratic non-residue
    z = 2
    while pow(z, (p-1)//2, p) != p-1:
        z += 1
    c = pow(z, Q, p)
    
    x = pow(n, (Q+1)//2, p)
    t = pow(n, Q, p)
    m = S
    while t != 1:
        # Find the least i such that t^(2^i) ≡ 1
        i, temp = 0, t
        while temp != 1 and i < m:
            temp = pow(temp, 2, p)
            i += 1
        
        if i == m:
            raise ValueError("No square root exists")
        
        b = pow(c, 1 << (m-i-1), p)
        x = (x * b) % p
        t = (t * b * b) % p
        c = (b * b) % p
        m = i
    
    return x

x, y = decompress_g1(bytes.fromhex("97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"))