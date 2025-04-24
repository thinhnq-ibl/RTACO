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