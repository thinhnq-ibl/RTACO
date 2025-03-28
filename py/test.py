def FindYforX_BLS12381(x):
    p = 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787
    beta = (pow(x, 3, p) + 4) % p
    y = pow(beta, (p + 1) // 4, p)
    return (beta, y)

def sqrt_bls12381(beta):
    p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    # Check if beta is a quadratic residue (Euler's criterion)
    legendre = pow(beta, (p - 1) // 2, p)
    if legendre != 1:
        raise ValueError("Beta is not a quadratic residue modulo p")
    # Compute square root using p ≡ 3 mod 4 shortcut
    y = pow(beta, (p + 1) // 4, p)
    return y

(beta, y) = FindYforX_BLS12381(4)
y = sqrt_bls12381(68)

print('x:', 4)
print('beta:', beta)
print('y:', y)
