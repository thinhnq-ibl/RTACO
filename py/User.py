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

ca_params = ttp_setup(q-1, vcert_title) # exclude r.

commit = GenCommitment(ca_params, encoded_attribute)

zkpok = GenZKPoK(ca_params, encoded_attribute, commit)

# send for CA do verify

result  = VerifyZKPoK(ca_params, encoded_attribute, commit, zkpok)
print("ZKPoK verification result: ", result)

pubCP, mskCP = ttpKeyGen(ca_params)
signature = SignCommitment(ca_params, mskCP, commit)
issueVcert = (commit, signature)
print("Signature: ", signature)

if(VerifyVcerts(ca_params, pubCP, signature, SHA256(commit)) == True):
    vcert["attributes"] = attributes
    vcert["commit"] = commit
    vcert["signature"] = signature
        
print(vcert)

ac_title = "Loan Credential"

params = setup(q, ac_title)
(sk, vk) = ttp_keygen(params, 1, 1)
aggregate_vk = agg_key(params, vk)
to = 1
no = 1
(opk, osk) = opener_keygen(params)
opks = [opk]
prevVcerts = []	
prevParams = []
all_encoded_attr = []
prevParams.append(ca_params)
prevVcerts.append((vcert["commit"], vcert["signature"]))
all_encoded_attr.append(encoded_attribute)

combination = ["Identity Certificate"]
include_indexes = [[1,0,0,1]]

Lambda, os = PrepareCredRequest(params, aggregate_vk, to, no, opks, prevParams, all_encoded_attr, include_indexes, public_m=[])
	
print("Lambda: ", Lambda)
print("os: ", os)

(cm, commitments, pi_s, hp, C, pi_o, Dw, Ew, hr, bo) = Lambda
#anything with "send" appended is making that particular variable as SC compatible.
send_cm = (cm[0].n, cm[1].n)
send_commitments = [(commitments[i][0].n, commitments[i][1].n) for i in range(len(commitments))]
send_ciphershares= [([([C[i][j][0].coeffs[1].n,C[i][j][0].coeffs[0].n],[C[i][j][1].coeffs[1].n, C[i][j][1].coeffs[0].n]) for j in range(2)],) for i in range(len(C))]
send_compressed_cipher = (send_commitments, send_ciphershares)
private_m = []
# schema = downloadSchema(title)
# schemaOrder = downloadSchemaOrder(title)
# for key in schemaOrder:
#     if schema[key]['visibility'] == 'private':
#         private_m.append(credential["attributes"][key])
private_m.append(vcert["attributes"][key1])
private_m.append(vcert["attributes"][key2])
send_hp =  [[(hp[i][j-1][0].n, hp[i][j-1][1].n) for j in range(1, to)] for i in range(len(private_m))]
send_hr = [(hr[i][0].n, hr[i][1].n) for i in range(len(hr))]
send_bo = [([bo[i][0].coeffs[1].n,bo[i][0].coeffs[0].n],[bo[i][1].coeffs[1].n,bo[i][1].coeffs[0].n]) for i in range(len(bo))]
send_Dw = [([Dw[i][0].coeffs[1].n,Dw[i][0].coeffs[0].n],[Dw[i][1].coeffs[1].n,Dw[i][1].coeffs[0].n]) for i in range(len(Dw))]
send_Ew = [([Ew[i][0].coeffs[1].n,Ew[i][0].coeffs[0].n],[Ew[i][1].coeffs[1].n,Ew[i][1].coeffs[0].n]) for i in range(len(Ew))]
send_compressed_G2Points = (send_Dw, send_Ew)
send_vcerts = [((prevVcerts[i][0][0].n, prevVcerts[i][0][1].n), prevVcerts[i][1]) for i in range(len(prevVcerts))]

pi_s = list(pi_s)
pi_s.append(combination)
pi_s = tuple(pi_s)

print("sending for verification")
public_m = []
public_m.append(vcert["attributes"][key3])
public_m.append(vcert["attributes"][key4])
str_public_m = [str(public_m[i]) for i in range(len(public_m))]