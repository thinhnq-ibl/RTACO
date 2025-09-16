import datetime
from TTP import *
from py_ecc_tester import *

import sys

import json

out = {}
encoding_type_map = {"1": type("string"), "2": type(1), "3": type(datetime.datetime.now())}

def genPreCert(msk, hs, attributes, encode_str, prevHs=[], prevVcerts=[], pre_encoded_attribute=[]):
    r = genRandom()
    
    for i in range(len(encode_str)):
        if encode_str[i] == 3:
            _date = datetime.datetime.strptime(attributes[i],"%Y-%m-%d").date()
            value_date = int(_date.strftime('%Y%m%d'))
            attributes[i] = value_date
            encode_str[i] = 2
            
    encoded_attribute = encode_attributes(attributes, encode_str)
    
    encoded_attribute.insert(0, msk)
    encoded_attribute.append(r)
    params = ((FQ, FQ2, FQ12), G1, int(curve_order), hs)
    commit = GenCommitment(params, encoded_attribute)

    prevAttributes = []
    prevAttributes.append([encoded_attribute[0], encoded_attribute[-1]])

    prevParams = [((FQ, FQ2, FQ12), G1, int(curve_order), hsi) for hsi in prevHs]
    zkpok = GenZKPoK(params, prevParams, prevVcerts, prevAttributes, commit)
    return (commit, zkpok)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        name = sys.argv[1]
        if name == "genRandom":
            msk = genRandom()
            out["msk"] = str(msk)
            print(json.dumps(out))
        elif name == "genPreCert":
            msk = int(sys.argv[2])
            hs = [get_g1_from_string(i) for i in sys.argv[3].split(',')]
            attributes = sys.argv[4].split(',')
            encode_str = [int(i) for i in sys.argv[5].split(',')]
            prevHs = [] if len(sys.argv) > 6 else []
            prevVcerts = [] if len(sys.argv) > 7 else []
            pre_encoded_attribute = [] if len(sys.argv) > 8 else []
            (commit, zkpok) = genPreCert(msk, hs, attributes, encode_str, prevHs, prevVcerts, pre_encoded_attribute)
            out["commit"] = get_g1_bytes(commit)
            out["zkpok_c"] = str(zkpok[0])
            out["zkpok_totalrm"] = [[str(j) for j in i] for i in zkpok[1]]
            print(json.dumps(out))
    else:
        print("Hello from Python!")