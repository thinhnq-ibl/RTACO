import datetime
from TTP import *
from py_ecc_tester import *

import sys

import json

out = {}
encoding_type_map = {"1": type("string"), "2": type(1), "3": type(datetime.datetime.now())}

def genPreCert(msk, hs, attributes, encode_strs, prevHs=[], pre_attributes =[],  pre_encode_strs=[], pre_commits = [], pre_signs = [], pre_r = []):
    r = genRandom()
    
    for i in range(len(encode_strs)):
        if encode_strs[i] == 3:
            _date = datetime.datetime.strptime(attributes[i],"%Y-%m-%d").date()
            value_date = int(_date.strftime('%Y%m%d'))
            attributes[i] = value_date
            encode_strs[i] = 2
            
    encoded_attribute = encode_attributes(attributes, encode_strs)

    encoded_attribute.insert(0, msk)
    encoded_attribute.append(r)

    params = ((FQ, FQ2, FQ12), G1, int(curve_order), hs)
    commit = GenCommitment(params, encoded_attribute)

    prevAttributes = []
    if len(pre_attributes) > 0:
        for i in range(len(pre_attributes)):
            pre_attribute = pre_attributes[i]
            pre_encode_str = pre_encode_strs[i]
            for j in range(len(pre_encode_str)):
                if pre_encode_str[j] == 3:
                    _date = datetime.datetime.strptime(pre_attribute[j],"%Y-%m-%d").date()
                    value_date = int(_date.strftime('%Y%m%d'))
                    pre_attribute[j] = value_date
                    pre_encode_str[j] = 2
            pre_vcert = encode_attributes(pre_attribute, pre_encode_str)
            pre_vcert.insert(0, msk)
            pre_vcert.append(pre_r[i])
            prevAttributes.append(pre_vcert)

    prevAttributes.append([encoded_attribute[0], encoded_attribute[-1]])
    prevParams = [((FQ, FQ2, FQ12), G1, int(curve_order), hsi) for hsi in prevHs]

    prevVcerts = []
    for i in range(len(pre_commits)):
        prevVcerts.append((pre_commits[i], pre_signs[i]))
    zkpok = GenZKPoK(params, prevParams, prevVcerts, prevAttributes, commit)
    return (commit, zkpok, r)

def genCredRequest(validator_hs, pre_list_hs, aggregate_vk, include_indexes, opks, all_encoded_attr, list_commit):
    prevParams = [ ((FQ, FQ2, FQ12), G1, int(curve_order), hs) for hs in pre_list_hs]
    to = 2
    no = 3
    validator_params = ((FQ, FQ2, FQ12), G1, int(curve_order), validator_hs)
    Lambda, os = PrepareCredRequest(validator_params, aggregate_vk, to, no, opks, prevParams, all_encoded_attr, include_indexes, public_m=[])

    (cm, commitments, pi_s, hp, C, pi_o, Dw, Ew, hr, bo) = Lambda

    combine_hs = []
    combine_commitments = []
    (c, rr, ros, total_rm) = pi_s
    for i in range(len(total_rm) - 1):
        _, ttp_g, _, ttp_hs = prevParams[i]
        combine_hs.append([get_g1_bytes(x) for x in ttp_hs])
        combine_commitments.append(get_g1_bytes(list_commit[i]))

    return [Lambda, combine_hs, combine_commitments]

if __name__ == "__main__":
    if len(sys.argv) > 1:
        name = sys.argv[1]
        if name == "genRandom":
            msk = genRandom()
            out["msk"] = str(msk)
            print(json.dumps(out))
        elif name == "genPreCert":
            msk = int(sys.argv[2])
            hs = json.loads(sys.argv[3])
            attributes = json.loads(sys.argv[4])
            encode_str = json.loads(sys.argv[5])
            pre_hs = json.loads(sys.argv[6])
            pre_attributes = json.loads(sys.argv[7])
            pre_encode_strs = json.loads(sys.argv[8])
            pre_commits = json.loads(sys.argv[9])
            pre_signs = json.loads(sys.argv[10])
            pre_r = json.loads(sys.argv[11])

            hs = get_list_g1_from_string(hs) 
            pre_hs = [get_list_g1_from_string(h) for h in pre_hs]

            pre_commits = get_list_g1_from_string(pre_commits)
            pre_sign_new = []
            for i in range(len(pre_signs)):
                pre_sign_new.append((int(pre_signs[i][0]), int(pre_signs[i][1]), get_g1_from_string(pre_signs[i][2])))
                
            new_pre_r = [int(i) for i in pre_r] 

            (commit, zkpok, r) = genPreCert(msk, hs, attributes, encode_str, pre_hs, pre_attributes, pre_encode_strs, pre_commits, pre_sign_new, new_pre_r)
            out["commit"] = get_g1_bytes(commit)
            out["zkpok_c"] = str(zkpok[0])
            out["zkpok_totalrm"] = [[str(j) for j in i] for i in zkpok[1]]
            out["r"] = str(r)
            print(json.dumps(out))

        elif name == "genCredRequest":
            val_hs = json.loads(sys.argv[3])
            pre_hs = json.loads(sys.argv[4])
            aggregate_vk = json.loads(sys.argv[5])
            include_indexes = json.loads(sys.argv[6])
            opks = json.loads(sys.argv[7])
            all_encoded_attr = json.loads(sys.argv[8])
            list_commit = json.loads(sys.argv[9])

            pre_hs = [get_list_g1_from_string(h) for h in pre_hs]
            val_hs = get_list_g1_from_string(val_hs)

            print(json.dumps(out))

    else:
        print("Hello from Python!")