from TTP import *
from py_ecc_tester import *
import datetime
import sys

import json

out = {}
encoding_type_map = {"1": type("string"), "2": type(1), "3": type(datetime.datetime.now())}

def genIdentitySchema():
    schema = {}
    schemaOrder = []
   
    key = "msk"
    schemaOrder.append(key)
    schema.setdefault(key, {"type" : "2", "visibility": "private"})

    key = "name"
    schemaOrder.append(key)
    schema.setdefault(key, {"type" : "1", "visibility": "private"})

    key = "dob"
    schemaOrder.append(key)
    schema.setdefault(key, {"type" : "3", "visibility": "private"})

    key = "r"
    schemaOrder.append(key)
    schema.setdefault(key, {"type" : "2", "visibility": "private"})

    q = len(schemaOrder) 

    params = ttp_setup(q-1, "Identity Certificate") # exclude r.
    pk, sk = ttpKeyGen(params)

    return {"schema": schema, "schemaOrder": schemaOrder, "name": "Identity Certificate", "params": get_list_g1_bytes(params[3]), "pk": get_g1_bytes(pk), "sk": str(sk)}

def genIncomeSchema():
    schema = {}
    schemaOrder = []

    key = "msk"
    schemaOrder.append(key)
    schema.setdefault(key, {"type" : "2", "visibility": "private"})

    key = "organization"
    schemaOrder.append(key)
    schema.setdefault(key, {"type" : "1", "visibility": "private"})

    key = "salary"
    schemaOrder.append(key)
    schema.setdefault(key, {"type" : "2", "visibility": "private"})

    key = "r"
    schemaOrder.append(key)
    schema.setdefault(key, {"type" : "2", "visibility": "private"})

    q = len(schemaOrder) 

    params = ttp_setup(q-1, "Income Certificate") # exclude r.
    pk, sk = ttpKeyGen(params)

    return {"schema": schema, "schemaOrder": schemaOrder, "name": "Income Certificate", "params": get_list_g1_bytes(params[3]), "pk": get_g1_bytes(pk), "sk": str(sk)}

def signAttributeCertificate(ttp_sk, ttp_hs, attributes, encode_str, commit, zkpok, prev_hs = [],  pre_commits = [], pre_signs = []):
    params = ((FQ, FQ2, FQ12), G1, int(curve_order), ttp_hs)
    prevParams = [((FQ, FQ2, FQ12), G1, int(curve_order), hsi) for hsi in prev_hs]

    for i in range(len(encode_str)):
        if encode_str[i] == 3:
            _date = datetime.datetime.strptime(attributes[i],"%Y-%m-%d").date()
            value_date = int(_date.strftime('%Y%m%d'))
            attributes[i] = value_date
            encode_str[i] = 2
            
    encoded_attribute = encode_attributes(attributes, encode_str)

    prevVcerts = []
    for i in range(len(pre_commits)):
        prevVcerts.append((pre_commits[i], pre_signs[i]))

    #params, prevParams, prevVcerts, encoded_attribute, commit,
    verify_zkp = VerifyZKPoK(params, prevParams, prevVcerts, encoded_attribute, commit, zkpok)
    if verify_zkp == False:
        return 

    # print ("verify_zkp", verify_zkp)
    signature = SignCommitment(params, ttp_sk, commit)
    return signature

if __name__ == "__main__":
    if len(sys.argv) > 1:
        name = sys.argv[1]
        if name == "genIdentitySchema":
            result = genIdentitySchema()
            out["schema"] = result["schema"]
            out["schemaOrder"] = result["schemaOrder"]
            out["name"] = result["name"]
            out["params"] = result["params"]
            out["pk"] = result["pk"]
            out["sk"] = result["sk"]
            print(json.dumps(out))
        elif name == "genIncomeSchema":
            result = genIncomeSchema()
            out["schema"] = result["schema"]
            out["schemaOrder"] = result["schemaOrder"]
            out["name"] = result["name"]
            out["params"] = result["params"]
            out["pk"] = result["pk"]
            out["sk"] = result["sk"]
            print(json.dumps(out))
        elif name == "signAttributeCertificate":
            ttp_sk = int(sys.argv[2])
            ttp_hs = json.loads(sys.argv[3])
            attributes = json.loads(sys.argv[4])
            encode_str = json.loads(sys.argv[5])
            user_commit = json.loads(sys.argv[6])
            zkpok_c = json.loads(sys.argv[7])
            zkpok_totalrm = json.loads(sys.argv[8])
            pre_hs = json.loads(sys.argv[9])
            pre_commits = json.loads(sys.argv[10])
            pre_signs = json.loads(sys.argv[11])

            user_commit = get_g1_from_string(user_commit)
            ttp_hs = get_list_g1_from_string(ttp_hs) 
            pre_hs = [get_list_g1_from_string(h) for h in pre_hs]

            pre_commits = get_list_g1_from_string(pre_commits)
            pre_sign_new = []
            for i in range(len(pre_signs)):
                pre_sign_new.append((int(pre_signs[i][0]), int(pre_signs[i][1]), get_g1_from_string(pre_signs[i][2])))
                
            zkpok = (int(zkpok_c), [[int(j) for j in i] for i in zkpok_totalrm])
            
            vcert = signAttributeCertificate(ttp_sk, ttp_hs, attributes, encode_str, user_commit, zkpok, pre_hs ,  pre_commits, pre_sign_new)
            # r, s, p1
            out["vcert_r"] = str(vcert[0])
            out["vcert_s"] = str(vcert[1])
            out["vcert_p1"] = get_g1_bytes(vcert[2])
            print(json.dumps(out))

    else:
        print("Hello from Python!")