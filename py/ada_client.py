import os

from blockfrost import ApiUrls, BlockFrostApi
from dotenv import load_dotenv
from pycardano import Address, Network, crypto, ExtendedSigningKey, PlutusV2Script, TransactionBuilder, TransactionOutput, plutus_script_hash, BlockFrostChainContext, Redeemer
import cbor2
from retry import retry

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

print(" ")
print("Staking enabled address:")
print("Payment Derivation path: m/1852'/1815'/0'/0/0")
print("Staking Derivation path: m/1852'/1815'/0'/2/0")

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

print(f"hash \t\t\t\t\t\t\t\t\t amount")
print(
    "--------------------------------------------------------------------------------------"
)

for utxo in utxos:
    tokens = ""
    for token in utxo.amount:
        if token.unit != "lovelace":
            tokens += f"{token.quantity} {token.unit} + "
    print(
        f"{utxo.tx_hash}#{utxo.tx_index} \t {int(utxo.amount[0].quantity)/1000000} ADA [{tokens}]"
    )

with open("fortytwoV2.plutus", "r") as f:
    script_hex = f.read()
    forty_two_script = PlutusV2Script(cbor2.loads(bytes.fromhex(script_hex)))


script_hash = plutus_script_hash(forty_two_script)

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
    print(tx)
    print(tx.to_cbor_hex())
    print("############### Submitting transaction ###############")
    chain_context.submit_tx(tx)
    wait_for_tx(str(tx.id))

# ----------- Send ADA to the script address ---------------
'''
builder = TransactionBuilder(chain_context)
builder.add_input_address(giver_address)
datum = 42
builder.add_output(TransactionOutput(script_address, 50000000, datum=datum))

signed_tx = builder.build_and_sign([payment_skey], giver_address)

print("############### Transaction created ###############")
print(signed_tx)
print("############### Submitting transaction ###############")
submit_tx(signed_tx)
'''
# ----------- Taker take ---------------

redeemer = Redeemer(42)

utxo_to_spend = None

# Spend the utxo with datum 42 sitting at the script address
for utxo in chain_context.utxos(script_address):
    print(utxo)
    if utxo.output.datum:
        utxo_to_spend = utxo
        break

# Find the reference script utxo
reference_script_utxo = None
for utxo in chain_context.utxos(giver_address):
    if utxo.output.script and utxo.output.script == forty_two_script:
        reference_script_utxo = utxo
        break

taker_address = staking_enabled_address

builder = TransactionBuilder(chain_context)

builder.add_script_input(utxo_to_spend, script=reference_script_utxo, redeemer=redeemer)
take_output = TransactionOutput(taker_address, 25123456)
builder.add_output(take_output)

signed_tx = builder.build_and_sign([payment_skey], taker_address)

print("############### Transaction created ###############")
print(signed_tx)
print("############### Submitting transaction ###############")
submit_tx(signed_tx)
