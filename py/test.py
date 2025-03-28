from py_ecc.bls12_381 import * 
from hashlib import sha256
import random

p = field_modulus

def FindYforX_BLS12381(x):
    beta = (pow(x, 3, p) + 4) % p
    y = pow(beta, (p + 1) // 4, p)
    return (beta, y)

def sqrt_bls12381(beta):
    
    # Check if beta is a quadratic residue (Euler's criterion)
    legendre = pow(beta, (p - 1) // 2, p)
    if legendre != 1:
        raise ValueError("Beta is not a quadratic residue modulo p")
    # Compute square root using p ≡ 3 mod 4 shortcut
    y = pow(beta, (p + 1) // 4, p)
    return y

def genRandom():
	o = int(p)
	return random.randint(2, o)

def hashG1(byte_string):
    beta = 0
    y = 0
    x = int.from_bytes(byte_string, "big") % curve_order
    while True :
        (beta, y) = FindYforX_BLS12381(x)
        if beta == pow(y, 2, field_modulus) :
            return (FQ(x), FQ(y))
        x = (x + 1) % field_modulus


(beta, y) = FindYforX_BLS12381(4)
y = sqrt_bls12381(68)

print('x:', 4)
print('beta:', beta)
print('y:', y)

hashG1(b'hello')