from dataclasses import dataclass
from pycardano import (
    Address,
    BlockFrostChainContext,
    Network,
    PaymentSigningKey,
    PlutusData,
    PlutusV3Script,
    ScriptHash,
    TransactionBuilder,
    TransactionOutput,
)
from pycardano.hash import (
    TransactionId,
    ScriptHash,
)
import json

from TTP_bls12 import *

from pycardano import Address, Network, PlutusV3Script, TransactionBuilder, TransactionOutput, BlockFrostChainContext, PlutusData
import json

from typing import List, Dict
from dataclasses import dataclass
import datetime

@dataclass
class IssueProof(PlutusData):
    CONSTR_ID = 0
    c: int
    rr: int
    ros: List[int]
    total_rm: List[List[int]]
    pubkeys: List[bytes]

@dataclass
class Sign(PlutusData):
    CONSTR_ID = 0
    r: int
    s: int
    r_g1: bytes

@dataclass
class Vcert(PlutusData):
    CONSTR_ID = 0
    commit: bytes
    r: int
    s: int
    r_g1: bytes
    # signature: Sign

@dataclass
class MyDatum(PlutusData):
    CONSTR_ID = 0
    vCert: List[Vcert]

@dataclass
class MyRedeemer(PlutusData):
    CONSTR_ID = 0
    iProof: IssueProof

##################################
## create vcert
##################################

msk = genRandom()
user_addr = "0x1A1684c3027eA12046155013BfC5518C65dD5943"

# Identity Certificate
vcert_title = "Identity Certificate"

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

# commit is G1 point
commit = GenCommitment(ca_params, encoded_attribute)

zkpok = GenZKPoK(ca_params, [], [], [encoded_attribute], commit)

# send for CA do verify
encoded_attribute_verify = [encoded_attribute[1], encoded_attribute[2]]
result  = VerifyZKPoK(ca_params, [], [], encoded_attribute_verify, commit, zkpok)

pubCP, mskCP = ttpKeyGen(ca_params)
signature = SignCommitment(ca_params, mskCP, commit)
issueVcert = (commit, signature)
# print("pubCP: ", pubCP)
pubkeyUncompress: G1Uncompressed = (FQO(pubCP[0].n),
                              FQO(pubCP[1].n), 
                              FQO(1))

if(VerifyVcerts(ca_params, pubCP, signature, SHA256(commit)) == True):
    vcert["attributes"] = attributes
    vcert["commit"] = commit
    vcert["signature"] = signature

commitUncompress: G1Uncompressed = (FQO(commit[0].n),
                              FQO(commit[1].n), 
                              FQO(1))

vcert1 = Vcert(
    commit = bytes.fromhex(i2osp(compress_G1(commitUncompress),48).hex()),
    r = signature[0],
    s = signature[1],
    r_g1 = bytes.fromhex(signature[2])# Convert pubkeyUncompress to bytes

)

# Income Certificate
vcert_title_income = "Income Certificate"

vcert_income = {"title":vcert_title_income, "attributes" : None, "commit": None, "signature": None}
attributes_income = {}
key1 = "msk"
value1 = msk
attributes_income.setdefault(key1, value1)
key2 = "r"
value2 = genRandom()
attributes_income.setdefault(key2, value2)
key5 = "salary"
value5 = 100000
attributes_income.setdefault(key5, value5)

attribute_income = []
encode_str_income = []

# make order for schema order
schemaOrder_income = ["msk", "salary", "r"]
# encode type 1: string, 2: int, 3: datetime
# prv key
attribute_income.append(attributes_income[key1])
encode_str_income.append(2) # int
# salary
attribute_income.append(attributes_income[key5])
encode_str_income.append(2) # int
# r
attribute_income.append(attributes_income[key2])
encode_str_income.append(2) # int

encoded_attribute_income = encode_attributes(attribute_income, encode_str_income)
q_income = len(schemaOrder_income)

prevCombination = [vcert["title"]]
prevParams = [ca_params]
prevVcerts = [(vcert["commit"], vcert["signature"])]
prevAttributes = [encoded_attribute]

ca_params_income = ttp_setup(q_income-1, vcert_title_income) # exclude r.

commit_income = GenCommitment(ca_params_income, encoded_attribute_income)
#print("commit_income", commit_income)
prevAttributes.append([attribute_income[0], attribute_income[-1]])

zkpok_income = GenZKPoK(ca_params_income, prevParams, prevVcerts, prevAttributes, commit_income)

# send for CA do verify income
encoded_attribute_income_verify = [encoded_attribute_income[1]]

result_income = VerifyZKPoK(ca_params_income, prevParams, prevVcerts, encoded_attribute_income_verify, commit_income, zkpok_income)
#print("ZKPoK verification income result: ", result_income)

pubCP2, mskCP2 = ttpKeyGen(ca_params_income)


pubkeyUncompress2: G1Uncompressed = (FQO(pubCP2[0].n),
                              FQO(pubCP2[1].n), 
                              FQO(1))
signature_income = SignCommitment(ca_params_income, mskCP2, commit_income)
#print("signature_income", signature_income)
issueVcertIncome = (commit_income, signature_income)
# #print("Signature: ", signature_income)

if(VerifyVcerts(ca_params_income, pubCP2, signature_income, SHA256(commit_income)) == True):
    vcert_income["attributes"] = attributes_income
    vcert_income["commit"] = commit_income
    vcert_income["signature"] = signature_income

commitUncompress2: G1Uncompressed = (FQO(commit_income[0].n),
                              FQO(commit_income[1].n), 
                              FQO(1))

vcert2 = Vcert(
    commit = bytes.fromhex(i2osp(compress_G1(commitUncompress2),48).hex()),
    r = signature_income[0],
    s = signature_income[1],
    r_g1 = bytes.fromhex(signature_income[2])# Convert pubkeyUncompress to bytes

)

datum_data = MyDatum(vCert = [vcert1, vcert2])

### prof ####
# print pubkey
pubkeyUncompress: G1Uncompressed = (FQO(pubCP[0].n),
                              FQO(pubCP[1].n), 
                              FQO(1))
print("pubkeyUncompress", i2osp(compress_G1(pubkeyUncompress),48).hex())
pubkeyUncompress2: G1Uncompressed = (FQO(pubCP2[0].n),
                              FQO(pubCP2[1].n), 
                              FQO(1))
print("pubkeyUncompress2", i2osp(compress_G1(pubkeyUncompress2),48).hex())
 
def read_validator() -> dict:
    with open("../plutus.json", "r") as f:
         script_hex = json.load(f)
    validators = script_hex["validators"]
    last_validator = filter(lambda x: x["title"] == "verify_simple_vcert.verify_simple_vcert.spend", validators)
    last_validator = list(last_validator)[0]
    script_bytes = PlutusV3Script(
        bytes.fromhex(last_validator["compiledCode"])
    )
    script_hash = ScriptHash(bytes.fromhex(last_validator["hash"]))
    return {
        "type": "PlutusV3",
        "script_bytes": script_bytes,
        "script_hash": script_hash,
    }
 
def lock(
    amount: int,
    into: ScriptHash,
    datum: PlutusData,
    signing_key: PaymentSigningKey,
    context: BlockFrostChainContext,
) -> TransactionId:
    # read addresses
    with open("me.addr", "r") as f:
        input_address = Address.from_primitive(f.read())
    contract_address = Address(
        payment_part = into,
        network=Network.TESTNET,
    )
 
    # build transaction
    builder = TransactionBuilder(context=context)
    builder.add_input_address(input_address)
    builder.add_output(
        TransactionOutput(
            address=contract_address,
            amount=amount,
            datum=datum,
        )
    )
    signed_tx = builder.build_and_sign(
        signing_keys=[signing_key],
        change_address=input_address,
    )
 
    # submit transaction
    return context.submit_tx(signed_tx)
 
context = BlockFrostChainContext(
    project_id="preprodXUnrdhNwv1yl0fKfF6AHcWt8e8ZqrTwb",
    base_url="https://cardano-preprod.blockfrost.io/api/",
)
 
signing_key = PaymentSigningKey.load("me.sk")
 
validator = read_validator()
 
 
tx_hash = lock(
    amount=10_000_000,
    into=validator["script_hash"],
    datum=datum_data,
    signing_key=signing_key,
    context=context,
)

print(
    f"10 tADA locked into the contract\n\tTx ID: {tx_hash}\n\tDatum: {datum_data.to_cbor_hex()}"
)