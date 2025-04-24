from TTP import *
import datetime

msk = genRandom()
user_addr = "0x1A1684c3027eA12046155013BfC5518C65dD5943"

vcert_title = "Identity Certificate"

# RequestVcert(title, requiredVcerts = []):
vcert = {"title":vcert_title, "attributes" : None, "commit": None, "signature": None}
attributes = {}
key1 = "msk"
value1 = msk
attributes.setdefault(key1, value1)
key2 = "r"
value2 = genRandom()
attributes.setdefault(key2, value2)
key3 = "name"
value3 = "Justin"
attributes.setdefault(key3, value3)
key4 = "dob"
value4 = "1998-05-12"
attributes.setdefault(key4, value4)

			
attribute = []
encode_str = []

# make order for schema order
schemaOrder = ["msk", "name", "dob", "r"]
# encode type 1: string, 2: int, 3: datetime
# prv key
attribute.append(attributes[key1])
encode_str.append(2) # int
# name
attribute.append(attributes[key3])
encode_str.append(1) # string
# DOB
_date = datetime.datetime.strptime(value4,"%Y-%m-%d").date()
value = int(_date.strftime('%Y%m%d'))
attribute.append(value)
encode_str.append(3) # datetime
# r
attribute.append(attributes[key2])
encode_str.append(2) # int

	
encoded_attribute = encode_attributes(attribute, encode_str)
q = len(schemaOrder)

params = ttp_setup(q-1, vcert_title) # exclude r.

commit = GenCommitment(params, encoded_attribute)

zkpok = GenZKPoK(params, encoded_attribute, commit)

# send for CA do verify

result  = VerifyZKPoK(params, encoded_attribute, commit, zkpok)
print("ZKPoK verification result: ", result)

pubCP, mskCP = ttpKeyGen(params)
signature = SignCommitment(params, mskCP, commit)
issueVcert = (commit, signature)
print("Signature: ", signature)

if(VerifyVcerts(params, pubCP, signature, SHA256(commit)) == True):
    vcert["attributes"] = attributes
    vcert["commit"] = commit
    vcert["signature"] = signature
        
print(vcert)