from TTP import *
from py_ecc_tester import *

import sys

import json

out = {}

if __name__ == "__main__":
    if len(sys.argv) > 1:
        name = sys.argv[1]
        if name == "genRandom":
            msk = genRandom()
            out["msk"] = str(msk)
            print(json.dumps(out))
    else:
        print("Hello from Python!")