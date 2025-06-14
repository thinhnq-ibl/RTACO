from dataclasses import dataclass
from pycardano import (
    Address,
    BlockFrostChainContext,
    Network,
    PaymentSigningKey,
    PaymentVerificationKey,
    PlutusData,
    PlutusV3Script,
    ScriptHash,
    TransactionBuilder,
    TransactionOutput,
    UTxO
)
from pycardano.hash import (
    VerificationKeyHash,
    TransactionId,
    ScriptHash,
)
import json
import sys

from TTP_bls12 import *
import datetime

from pycardano import Address, Network, PlutusV3Script, TransactionBuilder, TransactionOutput, BlockFrostChainContext, Redeemer, PlutusData



from py_ecc.bls.hash import (
    i2osp,
    os2ip
)
from py_ecc.bls.point_compression import (
    G1Uncompressed
)
from py_ecc.fields import (
    optimized_bls12_381_FQ as FQO,
)

from typing import List, Dict
from dataclasses import dataclass

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
#print("ZKPoK verification result: ", result)


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

@dataclass
class G2Point(PlutusData):
    CONSTR_ID = 1
    x: bytes
    y: bytes
@dataclass
class IssueProof(PlutusData):
    CONSTR_ID = 1
    c: int
    rr: int
    ros: List[int]
    total_rm: List[List[int]]
    pubkeys: List[bytes]

@dataclass
class Sign(PlutusData):
    CONSTR_ID = 1
    r: int
    s: int
    r_g1: bytes

@dataclass
class Vcert(PlutusData):
    CONSTR_ID = 1
    commit: G2Point
    signature: Sign

@dataclass
class MyDatum(PlutusData):
    CONSTR_ID = 1
    vCert: List[Vcert]

@dataclass
class MyRedeemer(PlutusData):
    CONSTR_ID = 0
    iProof: IssueProof

sign1 = Sign(
r = 1405393218543153634611558277146205543651389828460482046569307751654236783901042705626443752376987448075822652265738,
s = 38202479084295088188067894688129388712852808125955621239765113527621075572534,
r_g1 = bytes.fromhex("89218ac9d46dbef17651a764dd5e0ee7414b040221e3d0f188642129acfea1a17862de38851b2483095449c4732d150a")# Convert pubkeyUncompress to bytes
)
vcert1 = Vcert(
commit = G2Point(
    x = bytes.fromhex("1669f6cef337b4373a0f3e6307c6cdfb44517a36e125d7866ee9e838f4f5455cca63ce114d25b62ae4e597dc78c4db45"),
    y = bytes.fromhex("170d8abb0611028477e44388db31dccbee44f308b8f5cd934727ede4202b807fe1e7ba3c0d7c0680c9213dd84a29576d")
),
signature = sign1
)
sign2 = Sign(
r = 2552680529624568173590066327177950774551146809542008094226796730622167382728536331628983497397925589240933200869214,
s = 42372284252738667106345738865448192044614864058854813921958423275374058347560,
r_g1 = bytes.fromhex("9095c91e320d01fad00d33f26f19cfaa6e9d4a64a820bc2a854c72f3c72e3d47d55c418374daa130818e43c73a02b75e")  # Convert pubkeyUncompress to bytes
)

vcert2 = Vcert(
    commit = G2Point(
        x = bytes.fromhex("08f174c5102f45f9a4becc60fd8561d5948240ca3494830f20c143b4e116902bf633ebab064d90b920394a1588636aba"),
        y = bytes.fromhex("0e794a1e4e852485931858df9b034535078f94d6f68e4da286130dbef7d15d4cf5768718d703227c04dab741ef2b078e")
    ),
    signature = sign2
)

iproof = IssueProof(
    c = 111028293681481776174710511636606709440469689910069175151354337820721184534253,
    rr = 5050437177520903155847248449104124878646040665278897517070821451493842774601,
    ros = [
        49744196328279248815796712426546829894584294309244497450305853101602225222529,
        29782732702853354121904336237005215317539472786765989838419548536149186648559,
        3986513954939188089344606671398402557201798092878666912131712831328580791987,
        42926437779922011362364629289975177979465250943458230974890693324059432914956,
    ],
    total_rm = [
        [
            28570405751608929143275229779994869610628602755456909429086846981825913832910,              
            13507742991005023007096234598351915058180043055507780815574349619528610865134,
            26806696748710448407371037207606330670021875901994732626874438952060518010483,
            14337009862152980476725691075380459026334552202534707298997180022700568755898,
        ],
        [
            28570405751608929143275229779994869610628602755456909429086846981825913832910,
            45279309888158677857503732152612499548654948313017471839403896507493988578648,
            18631698991280989165794156185809282554249027473066654851015905870822852378043,          
        ],
    ],
    pubkeys = [
        bytes.fromhex("968cc0fcd3879a0b7b1f1f70fe60a7c5ea3aa45fcbb2d4963c5dec7b9efa5ec23be6ebf59f285d904d734afdf2f0147e"),
        bytes.fromhex("896b2e6fab0e737e1e299da5ea2cf9046883aaea3b4271bc0463f6cbe964be5b54f09325ee02caa704f7e71c03cd392a")
    ]
)

datum_data = MyDatum(vCert = [vcert1, vcert2])
redeemer_data = MyRedeemer(iProof = iproof)
 
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
 
def unlock(
    utxo: UTxO,
    from_script: PlutusV3Script,
    redeemer: Redeemer,
    signing_key: PaymentSigningKey,
    owner: VerificationKeyHash,
    context: BlockFrostChainContext,
) -> TransactionId:
    # read addresses
    with open("me.addr", "r") as f:
        input_address = Address.from_primitive(f.read())
 
    # build transaction
    builder = TransactionBuilder(context=context)
    builder.add_script_input(
        utxo=utxo,
        script=from_script,
        redeemer=redeemer,
    )
    builder.add_input_address(input_address)
    builder.add_output(
        TransactionOutput(
            address=input_address,
            amount=utxo.output.amount.coin,
        )
    )
    builder.required_signers = [owner]
    signed_tx = builder.build_and_sign(
        signing_keys=[signing_key],
        change_address=input_address,
    )
 
    # submit transaction
    return context.submit_tx(signed_tx)
 
def get_utxo_from_str(tx_id: str, contract_address: Address) -> UTxO:
    for utxo in context.utxos(str(contract_address)):
        if str(utxo.input.transaction_id) == tx_id:
            return utxo
    raise Exception(f"UTxO not found for transaction {tx_id}")
 
context = BlockFrostChainContext(
    project_id="preprodXUnrdhNwv1yl0fKfF6AHcWt8e8ZqrTwb",
    base_url="https://cardano-preprod.blockfrost.io/api/",
)
 
signing_key = PaymentSigningKey.load("me.sk")
 
validator = read_validator()
 
# get utxo to spend
utxo = get_utxo_from_str(sys.argv[1], Address(
    payment_part = validator["script_hash"],
    network=Network.TESTNET,
))
 
# build redeemer
# redeemer = Redeemer(data=HelloWorldRedeemer(msg=b"Hello, World!"))
redeemer = Redeemer(data=redeemer_data)
 
# execute transaction
tx_hash = unlock(
    utxo=utxo,
    from_script=validator["script_bytes"],
    redeemer=redeemer,
    signing_key=signing_key,
    owner=PaymentVerificationKey.from_signing_key(signing_key).hash(),
    context=context,
)
 
print(
    f"2 tADA unlocked from the contract\n\tTx ID: {tx_hash}\n\tRedeemer: {redeemer.to_cbor_hex()}"
)