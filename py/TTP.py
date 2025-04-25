from py_ecc.bn128 import * 
from hashlib import sha256
import random

def genRandom():
	o = int(curve_order)
	return random.randint(2, o)

def FindYforX(x) :
    beta = (pow(x, 3, field_modulus) + 3) % field_modulus
    y = pow(beta, (field_modulus + 1) //4, field_modulus)
    return (beta, y)

def hashG1(byte_string):
    beta = 0
    y = 0
    x = int.from_bytes(byte_string, "big") % curve_order
    while True :
        (beta, y) = FindYforX(x)
        if beta == pow(y, 2, field_modulus) :
            return (FQ(x), FQ(y))
        x = (x + 1) % field_modulus

def encode_attributes(attr, encode_str):
	o = int(curve_order)
	encoded_attr = []
	assert len(attr) == len(encode_str), "mismatch in encoding lengths"
	for i in range(len(attr)):
		if encode_str[i] == 1:
			Chash = sha256(attr[i].encode("utf8").strip()).digest()
			encoded_attr.append(int.from_bytes(Chash, "big") % o)
		else:
			encoded_attr.append(attr[i])
	return encoded_attr

def GenCommitment(params, encoded_attr):
	_, g, o, hs = params 
	Aw = [multiply(hs[i], encoded_attr[i]) for i in range(len(hs))]
	comm = multiply(g, encoded_attr[len(hs)])
	for i in range(0, len(Aw)):
		comm = add(comm, Aw[i])
	return comm

def ttp_setup(q, ttp):
	assert q > 0
	hs = [hashG1((ttp+("h%s")% i).encode("utf8")) for i in range(q)]
	return ((FQ, FQ2, FQ12), G1, int(curve_order), hs)

def toChallenge(element_list):
	"""Packages a challenge in a bijective way"""
	Cstring = SHA256(element_list[0])
	for i in range(1, len(element_list)):
		Cstring += SHA256(element_list[i])
	Chash = sha256(Cstring).digest()
	return (int.from_bytes(Chash, "big"))

def SHA256(element):
	return sha256((element[0].n).to_bytes(32, 'big') + (element[1].n).to_bytes(32, 'big')).digest()

def GenZKPoK(params, all_enc_attr, comm):
	_, g, o, hs = params
    # Generate random witnesses for the proof
	total_wm = [random.randint(2, o) for _ in range(len(all_enc_attr))]
	
    # Compute commitments (Aw) using the witnesses
	Aw = []
	
	# Compute commitment: g^{wm[-1]} * product(hs[j]^{wm[j]})
	commitment = multiply(g, total_wm[-1])
	for j in range(len(total_wm) - 1):
		commitment = add(commitment, multiply(hs[j], total_wm[j]))
	Aw.append(commitment)
    
    # Include the main commitment in the proof
	comm_list = [comm]
    
    # Generate challenge using all relevant elements
	element_list = [g] + Aw + comm_list + hs
	c = toChallenge(element_list) % o
    
    # Compute responses
	total_rm = []
	for wm, attr in zip(total_wm, all_enc_attr):
		total_rm.append((wm - c * attr) % o)
    # print(total_wm)
	return (c, total_rm)

def VerifyZKPoK(params, encoded_attr, comm, ZKPoK):
	c, total_rm = ZKPoK

    # Check that all first responses are equal (if multiple attribute sets)
	_, g, o, hs = params
    
    # Reconstruct the blinded commitment (tmp_comm)
	tmp_comm = multiply(hs[1], encoded_attr[0])
	for i in range(2, len(hs)):
		tmp_comm = add(tmp_comm, multiply(hs[i], encoded_attr[i-1]))
	tmp_comm = add(comm, neg(tmp_comm))  # comm - (sum hs[j] * attr[j])
    
    # Reconstruct Aw (commitments using responses)
	Aw = []
	commitment = multiply(g, total_rm[-1])
	for j in range(len(total_rm) - 1):
		commitment = add(commitment, multiply(hs[j], total_rm[j]))
	commitment = add(commitment, multiply(comm, c))
	Aw.append(commitment)
    
    # Generate challenge and verify
	element_list = [g] + Aw + [comm] + hs
	return (c == toChallenge(element_list) % o)

def SignCommitment(params, sk, comm):
	G, g, o, hs= params
	digest = SHA256(comm)
	sign = do_ecdsa_sign(sk, digest)
	return sign

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

def ttpKeyGen(params):
	_, g, o, hs = params
	sk = random.randint(2, o)
	pk = multiply(g, sk)
	return pk, sk

def VerifyVcerts(params, pk, sign, digest):
	return do_ecdsa_verify(pk, sign, digest)

def ttp_keygen(params, t, n):
    (G, o, g1, hs, g2, e) = params
    q = len(hs)
    assert n >= t and t > 0 and q > 0
    # generate polynomials
    v = [random.randint(2, o) for _ in range(0,t)]
    w = [[random.randint(2, o) for _ in range(0,t)] for _ in range(q)]
    # generate shares
    x = [poly_eval(v,i) % o for i in range(1,n+1)]
    y = [[poly_eval(wj,i) % o for wj in w] for i in range(1,n+1)]
    # set keys
    sk = list(zip(x, y))
    vk = [(g2, multiply(g2, x[i]), [multiply(g1, y[i][j]) for j in range(len(y[i]))], [multiply(g2, y[i][j]) for j in range(len(y[i]))]) for i in range(len(sk))]
    return (sk, vk)

def agg_key(params, vks):
    (G, o, g1, hs, g2, e) = params
    # filter missing keys (in the threshold setting)
    filter = [vks[i] for i in range(len(vks)) if vks[i] is not None]
    indexes = [i+1 for i in range(len(vks)) if vks[i] is not None]
    # evaluate all lagrange basis polynomials
    l = lagrange_basis(indexes,o)
    # aggregate keys
    (_, alpha, g1_beta, beta) = zip(*filter)
    q = len(beta[0])
    aggr_alpha = ec_sum([multiply(alpha[i], l[i]) for i in range(len(filter))])
    aggr_g1_beta = [ec_sum([multiply(g1_beta[i][j], l[i]) for i in range(len(filter))]) for j in range(q)]
    aggr_beta = [ec_sum([multiply(beta[i][j], l[i]) for i in range(len(filter))]) for j in range(q)]
    aggr_vk = (g2, aggr_alpha, aggr_g1_beta, aggr_beta)
    return aggr_vk

def lagrange_basis(indexes, o, x=0):
    """ generates all lagrange basis polynomials """
    l = []
    for i in indexes:
        numerator, denominator = 1, 1
        for j in indexes:
            if j != i:
                numerator = (numerator * (x - j)) % o
                denominator = (denominator * (i - j)) % o
        l.append((numerator * modInverse(denominator, o)) % o)
    return l

def setup(q=1, AC = "h"):
    assert q > 0
    hs = [hashG1((AC+"%s"%i).encode("utf8")) for i in range(q)]
    return ((FQ, FQ2, FQ12), curve_order, G1, hs, G2, pairing)

def poly_eval(coeff, x):
    """ evaluate a polynomial defined by the list of coefficient coeff at point x """
    return sum([coeff[i] * ((x) ** i) for i in range(len(coeff))])

def ec_sum(list):
    """ sum EC points list """
    ret = None
    if len(list) != 0:
        ret = list[0]
    for i in range(1,len(list)):
        ret = add(ret, list[i])
    return ret

def opener_keygen(params):
    (_, o, _, _, g2, _) = params
    z = random.randint(2, o)
    f = multiply(g2, z)
    return (f, z)

def encodeG2(g2):
	return (g2[0].coeffs[0].n, g2[0].coeffs[1].n, g2[1].coeffs[0].n, g2[1].coeffs[1].n)

def PrepareCredRequest(params, aggr_vk, to, no, opk, prevParams, all_attr, include_indexes, public_m=[]):
    private_m = []
    # for i in range(len(all_attr)):
    #     for j in range(len(all_attr[i])):
    #         if include_indexes[i][j] == 1:
    #             private_m.append(int(all_attr[i][j]))
    private_m.append(all_attr[0][0])
    private_m.append(all_attr[0][3])
    public_m.append(all_attr[0][1])
    public_m.append(all_attr[0][2])
    assert len(private_m) > 0
    (G, o, g1, hs, g2, e) = params
    attributes = private_m + public_m
    assert len(attributes) <= len(hs)
    # build commitment
    rand = random.randint(2, o)#generates random number 
    cm = add(multiply(g1, rand), ec_sum([multiply(hs[i], attributes[i]) for i in range(len(attributes))]))
    # build El Gamal encryption
    h = hashG1(to_binary256(cm))
    os = [random.randint(2, o) for _ in range(len(private_m))]#os is a "private_m" length random number array
    commitments = [add(multiply(g1, os[i]), multiply(h, private_m[i])) for i in range(len(private_m))]
    pi_s = make_pi_s(params, commitments, cm, os, rand, public_m, private_m, all_attr, prevParams, include_indexes)
    # build proofs
    # pi_s = make_pi_s(params, gamma, c, cm, k, r, public_m, private_m)
    # Lambda = (cm, c, pi_s)
    # opening information
    # generate polynomials to hide private attributes (m polynomials of degree 'to')
    P = [[random.randint(2, o) for _ in range(0, to)] for _ in range(len(private_m))]
    for i in range(len(private_m)):
        P[i][0] = private_m[i]
    #generate shares s[i] contains shares to ne shared with opener 'i'
    s = [[poly_eval(Pj,i) % o for Pj in P] for i in range(1,no+1)]
    hidden_P = [[multiply(h, P[i][j]) for j in range(1, to)] for i in range(len(private_m))]

    _, _, _, beta = aggr_vk
    r = [random.randint(2, o) for _ in range(no)]
    C = [(multiply(g2, r[i]), (add(multiply(opk[i], r[i]), ec_sum([multiply(beta[j], s[i][j]) for j in range(len(private_m))])))) for i in range(no)]
    
    Aw, Bw, pi_o = make_pi_o(params, cm, C, r, s, aggr_vk, opk)
    
    h_r = [multiply(h, ri) for ri in r]
    b_o = [multiply(beta[i], os[i]) for i in range(len(os))] 

    Lambda = (cm, commitments, pi_s, hidden_P, C, pi_o, Aw, Bw, h_r, b_o)
    return Lambda, os

def to_binary256(point) :
    if isinstance(point, str):
        return sha256(point.encode("utf8").strip()).digest()
    if isinstance(point, int):
        return point.to_bytes(32, 'big')
    if isinstance(point[0], FQ):
        point1 = point[0].n.to_bytes(32, 'big')
        point2 = point[1].n.to_bytes(32, 'big')
        return sha256(point1+point2).digest()
    if isinstance(point[0], FQ2):
        point1 = point[0].coeffs[0].n.to_bytes(32, 'big') + point[0].coeffs[1].n.to_bytes(32, 'big')
        point2 = point[1].coeffs[0].n.to_bytes(32, 'big') + point[1].coeffs[1].n.to_bytes(32, 'big')
        return sha256(point1+point2).digest()

def make_pi_s(params, commitments, cm, os, r, public_m, private_m, all_attr, prevParams, include_indexes):
    """ prove correctness of ciphertext and cm """
    (G, o, g1, hs, g2, e) = params
    attributes = private_m + public_m

    assert len(commitments) == len(os) and len(commitments) == len(private_m)
    assert len(attributes) <= len(hs)
    # create the witnesses
    wr =random.randint(2, o)
    wos = [random.randint(2, o) for _ in os]
    total_wm = [[random.randint(2, o) for _ in range(len(all_attr[i]))] for i in range(len(all_attr))]
    wm = []
    for i in range(len(all_attr)):
        for j in range(len(all_attr[i])):
            if include_indexes[i][j] == 1:
                wm.append(int(total_wm[i][j]))
    pub_wm = []
    for _ in public_m:
        pub_wm.append(random.randint(2,o))
    wm = wm + pub_wm
    total_wm.append(pub_wm)
    for i in range(1, len(total_wm)-1):
        total_wm[i][0] = total_wm[0][0]
    # compute h
    h = hashG1(to_binary256(cm))
    # compute the witnesses commitments
    Aw = [add(multiply(g1, wos[i]), multiply(h, wm[i])) for i in range(len(private_m))]
    Bw = add(multiply(g1, wr), ec_sum([multiply(hs[i], wm[i]) for i in range(len(attributes))]))
    Cw = []
    for i in range(len(total_wm) - 1):
        (_, ttp_g, _, ttp_hs) = prevParams[i]
        tmp = multiply(ttp_g, total_wm[i][-1])
        for j in range(len(total_wm[i]) - 1):
            tmp = add(tmp, multiply(ttp_hs[j], total_wm[i][j]))
        Cw.append(tmp)
    # create the challenge
    c = to_challenge([g1, g2, cm, h, Bw]+hs+Aw+Cw)
    # create responses
    rr = (wr - c * r) % o
    ros = [(wos[i] - c*os[i]) % o for i in range(len(wos))]
    total_rm = [[(total_wm[i][j] - c*all_attr[i][j]) % o for j in range(len(total_wm[i]))] for i in range(len(total_wm) - 1)]
    total_rm.append([(total_wm[-1][i] - c*public_m[i]) % o for i in range(len(total_wm[-1]))])
    # rm = [(wm[i] - c*attributes[i]) % o for i in range(len(wm))]
    return (c, rr, ros, total_rm)


def to_challenge(elements):
    _list = [to_binary256(x) for x in elements]
    Cstring = _list[0]
    for i in range(1, len(_list)):
        Cstring += _list[i]
    Chash =  sha256(Cstring).digest()
    return int.from_bytes(Chash, "big", signed=False)

def make_pi_o(params, cm, C, r, s, aggr_vk, opk):
    (G, o, g1, hs, g2, e) = params

    # assert len(ciphertext) == len(k) and len(ciphertext) == len(private_m)
    # assert len(ciphershares) == len(opk)
    # assert len(attributes) <= len(hs)
    # create the witnesses

    wr = [random.randint(2, o) for _ in r]
    ws = [[random.randint(2, o) for _ in s[i]] for i in range(len(s))]
    # compute h
    h = hashG1(to_binary256(cm))
    _, _, _, beta = aggr_vk
    # compute the witnesses commitments
    Aw = [multiply(g2, wri) for wri in wr]
    Bw = [add(multiply(opk[i], wr[i]), ec_sum([multiply(beta[j], ws[i][j]) for j in range(len(ws[i]))])) for i in range(len(ws))]

    # create the challenge
    c = []
    for i in range(len(wr)):
        c.append(to_challenge([g1, g2, h, Aw[i], Bw[i]]+ hs))

    rr = [(wr[i] - c[i]*r[i]) % o for i in range(len(wr))] 
    rs = [[(ws[i][j] - c[i]*s[i][j])% o for j in range(len(s[i]))] for i in range(len(s))]
    return (Aw, Bw, (c, rr, rs))

def BlindSignAttr(params, sk, Lambda, public_m=[]):
    (G, o, g1, hs, g2, e) = params
    (x, y) = sk
    (cm, commitments) = Lambda
    assert (len(commitments)+len(public_m)) <= len(hs)
    # verify proof of correctness
    # assert verify_pi_s(params, commitments, cm, all_vcerts, pi_s)
    #work from here in thr afternoon.
    # assert verify_pi_o(params, commitments, C, cm, hidden_P, h_r, b_o, aggr_vk, opk, pi_o)
    # issue signature
    h = hashG1(to_binary256(cm))
    print(public_m)
    t1 = [multiply(h, mi) for mi in public_m]
    t2 = add(multiply(h, x), ec_sum([multiply(bi, yi) for yi,bi in zip(y, commitments+t1)]))
    sigma_tilde = (h, t2)
    return sigma_tilde

def Unblind(params, aggr_vk, sigma_tilde, os):
    _, _, g1_beta, _ = aggr_vk
    (h, c_tilde) = sigma_tilde
    sigma = (h, add(c_tilde, neg(ec_sum([multiply(g1_beta[j], os[j]) for j in range(len(os))]))))
    return sigma

def AggCred(params, sigs):
    (G, o, g1, hs, g2, e) = params
    # filter missing credentials (in the threshold setting)
    filter = [sigs[i] for i in range(len(sigs)) if sigs[i] is not None]
    indexes = [i+1 for i in range(len(sigs)) if sigs[i] is not None]
    # evaluate all lagrange basis polynomials
    l = lagrange_basis(indexes,o)
    # aggregate sigature
    (h, s) = zip(*filter)
    aggr_s = ec_sum([multiply(s[i], l[i]) for i in range(len(filter))])
    aggr_sigma = (h[0], aggr_s)
    return aggr_sigma