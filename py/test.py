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

# (beta, y) = FindYforX_BLS12381(4)
# y = sqrt_bls12381(68)

# print('x:', 4)
# print('beta:', beta)
# print('y:', y)

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

# (x, y) = hashG1(b'hello')
# print('x,y:', x, y)

def modInverse(a, m):
    m0 = m
    y = 0
    x = 1
 
    if (m == 1):
        return 0
 
    while (a > 1):
        # q is quotient
        q = a // m
        t = m
 
        # m is remainder now, process
        # same as Euclid's algo
        m = a % m
        a = t
        t = y
 
        # Update x and y
        y = x - q * y
        x = t
 
    # Make x positive
    if (x < 0):
        x = x + m0
 
    return x

x = modInverse(3, 11)
print('x', x)

def modInverse2(a, m):
    """Modular inverse using extended Euclidean algorithm"""
    if a == 0:
        return 0
    lm, hm = 1, 0
    low, high = a % m, m
    while low > 1:
        ratio = high // low
        nm = hm - lm * ratio
        new = high - low * ratio
        hm, lm = lm, nm
        high, low = low, new
    return lm % m

x2 = modInverse2(3, 11)
print('x2', x2)

def generate_keypair():
    """Generate ECDSA private/public key pair on BLS12-381"""
    private_key = genRandom() % curve_order
    public_key = multiply(G1, private_key)
    return private_key, public_key

sk, pk = generate_keypair()
print('sk:', sk)
print('pk:', pk)

def do_ecdsa_sign(sk, digest):
	r = 0
	s = 0
	o = int(curve_order)
	int_digest = int.from_bytes(digest, "big") % o
	while r == 0 or s==0 :
		k = random.randint(2, o)
		p1 = multiply(G1, k)
		r = p1[0].n
		s = (modInverse(k, o) * (int_digest + ((sk * r) % o)) ) %o
	return (r, s)

sign = do_ecdsa_sign(sk, b'hello')
print(sign)

def do_ecdsa_verify(pk, sign, digest):
	(r, s) = sign
	o = int(curve_order)
	int_digest = int.from_bytes(digest, "big") % o
	s1 = modInverse(s, o)
	x1 = (int_digest * s1) % o
	x2 = (r * s1) % o
	pt1 = multiply(G1, x1)
	pt2 = multiply(pk, x2)
	_r = add(pt1, pt2)
	return r == _r[0].n

check = do_ecdsa_verify(pk , sign, b'hello')
print(check)


# def SHA256(element):
# 	return sha256((element[0].n).to_bytes(32, 'big') + (element[1].n).to_bytes(32, 'big')).digest()

# a = SHA256

# def SignCommitment(sk, comm):
# 	digest = SHA256(comm)
# 	sign = do_ecdsa_sign(sk, digest)
# 	return sign







