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

    else:
        print("Hello from Python!")