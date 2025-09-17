import datetime
from TTP import *
from py_ecc_tester import *

import sys

import json

out = {}

def genValidator(q, ac_title):
    validator_params = setup(q, ac_title)
    (_, _, _, hs, _, _) = validator_params
    tv = 2 #getThresholdValidators(args.title)
    nv = 3 #getTotalValidators(args.title)
    #q = getTotalAttributes(args.title)
    (sk, vk) = ttp_keygen(validator_params, tv, nv)
    # #print("sk, vk", sk, vk)
    aggregate_vk = agg_key(validator_params, vk)
    to = 2 #getThresholdOpeners(args.title) 
    no = 3 #getTotalOpeners(args.title)
    (opk, osk) = opener_keygen( validator_params)
    (opk1, osk1) = opener_keygen(validator_params)
    (opk2, osk2) = opener_keygen(validator_params)
    opks = [opk, opk1, opk2,]
    osks = [osk, osk1, osk2]

    return (hs, sk, vk, aggregate_vk, opks, osks)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        name = sys.argv[1]
        if name == "genValidator":
            q = int(sys.argv[2])
            ac_title = json.loads(sys.argv[3])
            (hs, sk, vk, aggregate_vk, opks, osks) = genValidator(q, ac_title)
            out["hs"] = [str (i ) for i in hs]
            print(json.dumps(out))
    else:
        print("Hello from Python!")