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

def signAttributeCertificate(ttp_sk, ttp_hs, attributes, encode_str, commit, zkpok, prev_hs = []):
    params = ((FQ, FQ2, FQ12), G1, int(curve_order), ttp_hs)
    prevParams = [((FQ, FQ2, FQ12), G1, int(curve_order), hsi) for hsi in prev_hs]

    for i in range(len(encode_str)):
        if encode_str[i] == 3:
            _date = datetime.datetime.strptime(attributes[i],"%Y-%m-%d").date()
            value_date = int(_date.strftime('%Y%m%d'))
            attributes[i] = value_date
            encode_str[i] = 2
            
    encoded_attribute = encode_attributes(attributes, encode_str)

    verify_zkp = VerifyZKPoK(params, [], [], encoded_attribute, commit, zkpok)
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
            ttp_hs = [get_g1_from_string(i) for i in sys.argv[3].split(',')]
            attributes = sys.argv[4].split(',')
            encode_str = [int(i) for i in sys.argv[5].split(',')]
            user_commit = get_g1_from_string(sys.argv[6])
            zkpok_c = int(sys.argv[7])
            zkpok_totalrm = [[int(j) for j in i.split(',')] for i in sys.argv[8].split(';')]
            zkpok = (zkpok_c, zkpok_totalrm)
            vcert = signAttributeCertificate(ttp_sk, ttp_hs, attributes, encode_str, user_commit, zkpok)
            # r, s, p1
            out["vcert_r"] = str(vcert[0])
            out["vcert_s"] = str(vcert[1])
            out["vcert_p1"] = get_g1_bytes(vcert[2])
            print(json.dumps(out))

    else:
        print("Hello from Python!")