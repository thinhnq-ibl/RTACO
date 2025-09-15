from TTP import *
from py_ecc_tester import *
import datetime
import sys

import json

out = {}

def genIdentitySchema():
    schema = {}
    encoding = {}
    schemaOrder = []
   
    encoding_type_map = {"1": type("string"), "2": type(1), "3": type(datetime.datetime.now())}

    key = "msk"
    schemaOrder.append(key)
    schema.setdefault(key, {"type" : "2", "visibility": "private"})
    encoding.setdefault(key, 2)

    key = "name"
    schemaOrder.append(key)
    schema.setdefault(key, {"type" : "1", "visibility": "private"})
    encoding.setdefault(key, 1)

    key = "dob"
    schemaOrder.append(key)
    schema.setdefault(key, {"type" : "3", "visibility": "private"})
    encoding.setdefault(key, 3)

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

    else:
        print("Hello from Python!")