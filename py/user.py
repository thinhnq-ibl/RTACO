import datetime
from TTP import *
from py_ecc_tester import *

import sys

import json

out = {}
encoding_type_map = {"1": type("string"), "2": type(1), "3": type(datetime.datetime.now())}

def genCommitZKP(msk, params, attributes, encode_str, prevParams=[], prevVcerts=[], pre_encoded_attribute=[]):
    r = genRandom()
    encoded_attribute = encode_attributes(attributes, encode_str)
    encoded_attribute.insert(0, msk)
    encoded_attribute.append(r)
    commit = GenCommitment(params, encoded_attribute)

    prevAttributes = [pre_encoded_attribute]
    prevAttributes.append([encoded_attribute[0], encoded_attribute[-1]])

    zkpok = GenZKPoK(params, prevParams, prevVcerts, prevAttributes, commit)
    return (commit, zkpok)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        name = sys.argv[1]
        if name == "genRandom":
            msk = genRandom()
            out["msk"] = str(msk)
            print(json.dumps(out))
        elif name == "genCommitZKP":
            msk = int(sys.argv[2])
            params = json.loads(sys.argv[3])
            attributes = json.loads(sys.argv[4])
            encode_str = sys.argv[5]
            prevParams = json.loads(sys.argv[6]) if len(sys.argv) > 6 else []
            prevVcerts = json.loads(sys.argv[7]) if len(sys.argv) > 7 else []
            pre_encoded_attribute = json.loads(sys.argv[8]) if len(sys.argv) > 8 else []
            (commit, zkpok) = genCommitZKP(msk, params, attributes, encode_str, prevParams, prevVcerts, pre_encoded_attribute)
            out["commit"] = str(commit)
            out["zkpok"] = str(zkpok)
            print(json.dumps(out))
    else:
        print("Hello from Python!")