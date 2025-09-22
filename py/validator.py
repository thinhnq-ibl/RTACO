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

    vk_byte = [[get_g2_bytes(i[0]), get_g2_bytes(i[1]), get_list_g1_bytes(i[2]), get_list_g2_bytes(i[3])]for i in vk]
    aggregate_vk_byte = [get_g2_bytes(aggregate_vk[0]), get_g2_bytes(aggregate_vk[1]), get_list_g1_bytes(aggregate_vk[2]), get_list_g2_bytes(aggregate_vk[3])]

    return (hs, [[str(i[0]), [str(j) for j in i[1]]] for i in sk], vk_byte, aggregate_vk_byte, get_list_g2_bytes(opks), [str(i) for i in osks])

if __name__ == "__main__":
    if len(sys.argv) > 1:
        name = sys.argv[1]
        if name == "genValidator":
            q = int(sys.argv[2])
            ac_title = json.loads(sys.argv[3])
            (hs, sk, vk, aggregate_vk, opks, osks) = genValidator(q, ac_title)
            out["hs"] = [get_g1_bytes (i ) for i in hs]
            out["sk"] = sk
            out["vk"] = vk
            out["aggregate_vk"] = aggregate_vk
            out["opks"] = opks
            out["osks"] = osks
            print(json.dumps(out))
    else:
        print("Hello from Python!")