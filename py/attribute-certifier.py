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

    return {"schema": schema, "schemaOrder": schemaOrder}

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

    # print("Schema:", schema)
    # print("Schema Order:", schemaOrder)

    return {"schema": schema, "schemaOrder": schemaOrder}

if __name__ == "__main__":
    if len(sys.argv) > 1:
        name = sys.argv[1]
        if name == "genIdentitySchema":
            result = genIdentitySchema()
            out["schema"] = result["schema"]
            out["schemaOrder"] = result["schemaOrder"]
            print(json.dumps(out))
        elif name == "genIncomeSchema":
            result = genIncomeSchema()
            out["schema"] = result["schema"]
            out["schemaOrder"] = result["schemaOrder"]
            print(json.dumps(out))

    else:
        print("Hello from Python!")