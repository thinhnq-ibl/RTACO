from py_ecc.bn128 import * 
from hashlib import sha256
import random

def genRandom():
	o = int(curve_order)
	return random.randint(2, o)