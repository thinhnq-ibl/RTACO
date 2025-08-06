import os
from blockfrost import ApiUrls, BlockFrostApi
from dotenv import load_dotenv
from pycardano import Address, Network, crypto, ExtendedSigningKey, PlutusV3Script, TransactionBuilder, TransactionOutput, plutus_script_hash, BlockFrostChainContext, Redeemer, PlutusData, ExecutionUnits
import json
import cbor2

from typing import List, Dict
from dataclasses import dataclass

from retry import retry
import json


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

load_dotenv()
network = os.getenv("network")
wallet_mnemonic = os.getenv("wallet_mnemonic")
blockfrost_api_key = os.getenv("blockfrost_api_key")

if network == "testnet":
    base_url = ApiUrls.preprod.value
    cardano_network = Network.TESTNET
else:
    base_url = ApiUrls.mainnet.value
    cardano_network = Network.MAINNET


new_wallet = crypto.bip32.HDWallet.from_mnemonic(wallet_mnemonic)
payment_key = new_wallet.derive_from_path(f"m/1852'/1815'/0'/0/0")
staking_key = new_wallet.derive_from_path(f"m/1852'/1815'/0'/2/0")
payment_skey = ExtendedSigningKey.from_hdwallet(payment_key)
staking_skey = ExtendedSigningKey.from_hdwallet(staking_key)


print("Enterprise address (only payment):")
print("Payment Derivation path: m/1852'/1815'/0'/0/0")

enterprise_address = Address(
    payment_part=payment_skey.to_verification_key().hash(), network=cardano_network
)
print(enterprise_address)

# print(" ")
# print("Staking enabled address:")
# print("Payment Derivation path: m/1852'/1815'/0'/0/0")
# print("Staking Derivation path: m/1852'/1815'/0'/2/0")

staking_enabled_address = Address(
    payment_part=payment_skey.to_verification_key().hash(),
    staking_part=staking_skey.to_verification_key().hash(),
    network=cardano_network,
)
print(staking_enabled_address)

main_address = staking_enabled_address
print(" ")
print(f"Derived address: {main_address}")
print(" ")

api = BlockFrostApi(project_id=blockfrost_api_key, base_url=base_url)

try:
    utxos = api.address_utxos(main_address)
except Exception as e:
    if e.status_code == 404:
        print("Address does not have any UTXOs. ")
        if network == "testnet":
            print(
                "Request tADA from the faucet: https://docs.cardano.org/cardano-testnets/tools/faucet/"
            )
    else:
        print(e.message)
    sys.exit(1)


for utxo in utxos:
    tokens = ""
    for token in utxo.amount:
        if token.unit != "lovelace":
            tokens += f"{token.quantity} {token.unit} + "
    print(
        f"{utxo.tx_hash}#{utxo.tx_index} \t {int(utxo.amount[0].quantity)/1000000} ADA [{tokens}]"
    )

with open("../plutus.json", "r") as f:
    script_hex = json.load(f)
    validators = script_hex["validators"]
    last_validator = filter(lambda x: x["title"] == "iith.iith.spend", validators)
    last_validator = list(last_validator)[0]
    forty_two_script = PlutusV3Script(cbor2.loads(bytes.fromhex(last_validator["compiledCode"])))
print(f"Script: {last_validator['title']}")
print(f"Hash: {last_validator['hash']}")

script_hash = plutus_script_hash(forty_two_script)
print(f"Script hash: {script_hash}")

script_address = Address(script_hash, network = cardano_network)

giver_address = staking_enabled_address

chain_context = BlockFrostChainContext(
    project_id=blockfrost_api_key,
    base_url=base_url,
)

@retry(delay=20)
def wait_for_tx(tx_id):
    chain_context.api.transaction(tx_id)
    print(f"Transaction {tx_id} has been successfully included in the blockchain.")


def submit_tx(tx):
    print("############### Transaction created ###############")
    # print(tx)
    print(tx.to_cbor_hex())
    print("############### Submitting transaction ###############")
    chain_context.submit_tx(tx)
    wait_for_tx(str(tx.id))

### 
# Todo: #1
# Create a transaction to create request credential

@dataclass
class IssueProof(PlutusData):
    CONSTR_ID = 0
    c: int
    rr: int
    ros: List[int]
    total_rm: List[List[int]]
    pubkeys: List[bytes]

@dataclass
class OpenProof(PlutusData):
    CONSTR_ID = 0
    dw: List[List[bytes]]
    ew: List[List[bytes]]
    c: List[int]

@dataclass
class Sign(PlutusData):
    CONSTR_ID = 0
    r: int
    s: int
    r_g1: bytes

@dataclass
class Vcert(PlutusData):
    CONSTR_ID = 0
    commit: List[bytes]
    signature: Sign

@dataclass
class BlindSignDatum(PlutusData):
    CONSTR_ID = 0
    iproof: IssueProof
    open: OpenProof
    vcerts: List[Vcert]
    cm_compressed: bytes
    h_compressed: bytes
    hs_compressed: List[bytes]
    include_indexes: List[List[int]]
    cw: List[bytes]
    commits_compressed: List[bytes]

@dataclass
class Redeem(PlutusData):
    CONSTR_ID = 0
    mode: int

blindSignDtatum = BlindSignDatum(
    iproof=IssueProof(
        c=42535636952854378490874194418722333779152010990979182213475440387396116429547,
        rr=40675462214123865742431951389911046237865684117786381568714250885257348136441,
        ros=[
            47925282862226222643927521835608820926632670018838597296086614014727602246558,
            21687859965734279473419411257190997575311278370788120793865541862802550871605,
        ],
        total_rm=[
            [
                50308106295266800020532960251996643677383528606831312922664123595083067330785,
                5095311348487787861645372845191969718727204196912877257125842030966424005608,
                24215618229245167673429987719866984434968409701328374910407976599467102132405,
                23117088388493107445729512963030794110283280127530426202939187508228779289686,
            ],
            [
                50308106295266800020532960251996643677383528606831312922664123595083067330785,
                40928904529511035926773476820862854867207669516607935231354640227867095612728,
                25499875010848260697670552620696378616666315278639900420553745755017069746308,
            ],
            []
        ],
        pubkeys=[
            bytes.fromhex("a97b2135da7799823236baea87402c5cc00e3a61c99e9abf7c2d9c0c29d1c50fd5753e3076c5e3da091c861199ee72b7"),
            bytes.fromhex("b51cc7408bc47ad537c29fef899a73b784de41c2063d5aac5248623f3db3dd4131e1cd9af902d49b28bc38819ffb48eb")
        ]
    ),
    open=OpenProof(
         dw = [
        [
          bytes.fromhex("b7d202145af60c01a1294e20a824ec0ff5a8bb3c8960a0862714fdad6f1d72afeb38c2ef9ede0efa80f4bc530e361c05"),
          bytes.fromhex("12f07e97e697747ff1732948b6a9588f0502bc78d5ebcfbc0ccbd599f12fa73086711a758e32c29ed65671cc75a4b742"),
        ],
        [
          bytes.fromhex("b17404753763b1a7a2c8f3eda805c94e7e5726ca2d8850fcc64e7da63501f228ddbaba2646761505034b41133f106f00"),
          bytes.fromhex("192f783e17209bfbf58196e6a81edf05d5694ea016a559aa8c1ea70a7e6a31320037b88e8f19d125bcadf9120e214fc6"),
        ],
        [
          bytes.fromhex("a9b246d918b61b40990060eed918839eed12404dcd4e8fee55fde61aa5f7f532e6aa46fb89a8558c5997497c130ba1c9"),
          bytes.fromhex("13fb095a31ee0b02fb61b2e991027909810cd6140056cd47dc6ab5a8f8f9cdd48bf71683fe6315854992041cc5f32426"),
        ],
      ],
      ew= [
        [
          bytes.fromhex("b21b44aa690efa4366df2bab175f0f29dd58f3f05848199f1870b9a857a20cc0de9d862a9e773f6c0733b7582a8d3dec"),
          bytes.fromhex("0838b6c4c31121fc67a63f0a56f607cdbd9fbf6de1fbc81f89b2a0a2e967facc671c9e8bdf5341c5ab1b1b36e4a0618f"),
        ],
        [
          bytes.fromhex("a24e10a1f880d42e061513da1d224d009139b2aa1d52b7cc8b603c316a6a43f2d1a9862cf95cd59bf8aaf7e9fe5f0ccd"),
          bytes.fromhex("0d24adec785a3adea053b05e3c8a0369f5b95568b2ef8092e4aafaef6d4d5546f43e05133d0624956f9e6264e070b17c"),
        ],
        [
          bytes.fromhex("974932069a948e5776dd4d7928b26840a8188012ced6894a454552ddb6abf2b2dc946e56b8c493f7bec43fe5e69070f7"),
          bytes.fromhex("0a01382b44ed8653af6190c303009f2bf51f60eaa0f171fb3a24274515202d81baf143e4b17e276723a40574449af4e9"),
        ],
      ],
        c = [
            13804325079850457725627142957951104827873126539730078258784195038440940880392,
            11726514466030405860930521000683610778958399959004350468181692188389284878278,
            51432526391402064059818130005060767434915237470275281612051755280949532972757,
        ]
    ),
    vcerts=[
        Vcert(
            commit=[
                bytes.fromhex("075320f826a216c87da892bfc8aaacd2a75f5ccdfa62b72de3491b0bf079201a2def1fc9f18234df324976fdaf267870"),
                bytes.fromhex("112bdf0ec3b461ae5bf50d9d0cde259cfdaa4789a6a7595dc3a37a76d6bc7c11d14cfb7528a60ea753bba5e501af4d5a"),
            ],
            signature=Sign(
                r=1947564745249895947708144629914312558157305610980073189304752255321217468940983390413315295194393892376039785033790,
                s=17355617863143591184525546256817223357573510192270296979117455415910592064385,
                r_g1=bytes.fromhex("aca7513f4288ab39cdb45202f54678d9bd5d815b52295dc7f22b16c7572e13b93d96b6837288a909d801ce61a638f03e")
            )
        ),
        Vcert(
            commit=[
                bytes.fromhex("03324843cb50de5ba1dc8202d2f122a079857340727e63ad1227c3c9068acbd6039d452a6cf8b49405bd895c528582f3"),
                bytes.fromhex("19de1c7c436db928c356fc685aa32832ade4583760476d176f366c0fd5b92d4b93256afd144d2f815abd721d497d2aee"),
            ],
            signature=Sign(
                r=3924284939951961681834764047095286118299427666162894647982549458393534809915388538121180076697345644595416192308475,
                s=30161833219843676097829195363654408677477538928028790969163359605163750361918,
                r_g1=bytes.fromhex("b97f20c47b4d12e53f6cb898067b63532e53c906b200f2638db569a7d50977a7fbb53609e324b65a9934b3d08960d4fb")
            )
        )
    ],
    cm_compressed=bytes.fromhex("b3ff7f0d403bd9735aaaf54e14ab8409766572dd7343a04703e764fec9be90a082d7a5c2b92b9fca149412e982db8efd"),
    h_compressed=bytes.fromhex("b8ed5b8f9dc605471fd4a9d373318d0a4b230722169aacdeda85a6ad0c0c3ebfe6fa58a16b062086368437cf8d45f185"),
    hs_compressed=[
        bytes.fromhex("a090cfe9261fdcfbe1b0b3f74256e57f6a5bdd98c13b0e09f9484838b02239a0ab8b883b7910585c13918f995eb8df89"),
        bytes.fromhex("865341b6a4affbe3b795d2d3c71781ad7267849fe2b24e728e13524d60d08e5a1681344b20268ea337d2fa2c1c3bbd7c")
    ],
    include_indexes=[
        [0, 0, 1, 0], [0, 1, 0]
    ],
    cw=[
        bytes.fromhex("8bf40d9b47562565fbe0bbbf2c12f0ea74da8be42010895d003c5f770cf757f18bbadd34e00e97dca0d9b2bf128738de"),
        bytes.fromhex("b33f8d0af6f8a5def6c26579645803e9d12cd4498ca4be50179566c5cdce4493fd36ee62b2016ad9ffb3b1e4f5ef5bef"),
    ],
    commits_compressed=[
        bytes.fromhex("83a30f27817b9a06550b8d7f81b5594281f35259660f30c9ebf4b09a7a249c644ab2918432e90b0d0c2887f25f14aceb"),
        bytes.fromhex("b0b3013fd69e7d201c862e9e4e5308ba7d4d39a2a602c384660a0cfbddb09dc5c167a2d07ee02f8e73b9a996012b5992"),
    ]
)

datum_data = blindSignDtatum

def request_credential(chain_context, payment_skey, giver_address, script_address):
    builder = TransactionBuilder(chain_context)
    builder.add_input_address(giver_address)

    datum_data = 1

    builder.add_output(TransactionOutput(script_address, 50000000, datum = datum_data))

    signed_tx = builder.build_and_sign([payment_skey], giver_address)

    print("############### Submitting transaction ###############")
    submit_tx(signed_tx)
    # 616e05ae68b8befde5bf425aa95e1950a43d29e38a3f91936f74cecb2675fc9f
# request_credential(chain_context, payment_skey, giver_address, script_address)
# Todo: #2
# Using datum from request credential UTXO
# Create a transaction to issue blind sign + verify request credential = partial credential
# Aggregate partial credentials into a full credential

def issue_blind_sign(chain_context, payment_skey, script_address):
    # Spend the utxo with datum 42 sitting at the script address
    utxo_to_spend = None
    for utxo in chain_context.utxos(script_address):
        if utxo.input.transaction_id.to_primitive()==  bytes.fromhex("6bce32f4a9121b86617179651abe912487da05035367d64422ab2d4fef75470e"):
            # print(utxo)
            utxo_to_spend = utxo
            break
    print("utxo_to_spend", utxo_to_spend)

    # # Find the reference script utxo
    # reference_script_utxo = None
    # for utxo in chain_context.utxos(giver_address):
    #     if utxo.output.script and utxo.output.script == forty_two_script:
    #         reference_script_utxo = utxo
    #         break
    # # print("reference_script_utxo", reference_script_utxo)

   

    taker_address = staking_enabled_address

    redeemer = Redeemer(Redeem(mode=44), ExecutionUnits(5000000, 1000000))

    builder = TransactionBuilder(chain_context)
    builder.add_script_input(utxo_to_spend, script=forty_two_script, redeemer=redeemer)
    # builder.add_input_address(taker_address)

    take_output = TransactionOutput(taker_address, 40123456)
    builder.add_output(take_output)
    builder.required_signers = [payment_skey.to_verification_key().hash()]
    signed_tx = builder.build_and_sign([payment_skey], taker_address)

    print("############### Submitting transaction ###############")
    submit_tx(signed_tx)

issue_blind_sign(chain_context, payment_skey, script_address)
# Todo: #3
# Using datum from blind sign UTXO
# Create a transaction to verify full credential
###
