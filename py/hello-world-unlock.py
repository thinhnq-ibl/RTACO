from dataclasses import dataclass
from pycardano import (
    Address,
    BlockFrostChainContext,
    Network,
    PaymentSigningKey,
    PaymentVerificationKey,
    PlutusData,
    PlutusV3Script,
    Redeemer,
    ScriptHash,
    TransactionBuilder,
    TransactionOutput,
    UTxO,
)
from pycardano.hash import (
    VerificationKeyHash,
    TransactionId,
    ScriptHash,
)
import json
import os
import sys
 
def read_validator() -> dict:
    with open("../plutus.json", "r") as f:
         script_hex = json.load(f)
    validators = script_hex["validators"]
    last_validator = filter(lambda x: x["title"] == "hello_word.hello_world.spend", validators)
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
 
@dataclass
class HelloWorldRedeemer(PlutusData):
    CONSTR_ID = 0
    msg: bytes
 
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
redeemer = Redeemer(data=HelloWorldRedeemer(msg=b"Hello, World!"))
 
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