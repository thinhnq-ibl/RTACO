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

from pycardano import Address, Network, PlutusV3Script, TransactionBuilder, TransactionOutput, BlockFrostChainContext, Redeemer, PlutusData

from typing import List, Dict
from dataclasses import dataclass


@dataclass
class IssueProof(PlutusData):
    CONSTR_ID = 0
    c: int
    rr: int
    ros: List[int]
    total_rm: List[List[int]]
    pubkeys: List[bytes]

@dataclass
class MyRedeemer(PlutusData):
    CONSTR_ID = 0
    iProof: IssueProof

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
        bytes.fromhex("ad6eda411d6ab2b655921c1f93d5599a1bdadda73175d60b87194749c754d296656b4d1628a6deac85f3c7686df55e21"),
        bytes.fromhex("b6619de777b87bb85624f2360b489a5458a271f366aa0d00e4b0eee5b0d8bbc0fd0e4ff948ed1ac1c1efb8f460066abc")
    ]
)

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