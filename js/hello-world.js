import {
  Lucid,
  Blockfrost,
  Data,
  Constr,
  fromText,
} from "@evolution-sdk/lucid";

import { getAddressDetails, validatorToAddress } from "@evolution-sdk/utils";

const lucid = await Lucid(
  new Blockfrost(
    "https://cardano-preprod.blockfrost.io/api/v0",
    "preprodXUnrdhNwv1yl0fKfF6AHcWt8e8ZqrTwb"
  ),
  "Preprod"
);

let seedPhrase =
  "duck process cigar amount dumb foam verb raven carry nurse icon lunar oil suit pencil message hip call program you wet grass inside bean"; // Replace with your actual seed phrase
lucid.selectWallet.fromSeed(seedPhrase);

const address = await lucid.wallet().address(); // Bech32 address
console.log("Wallet address:", address);

const pubKeyHash = getAddressDetails(address).paymentCredential.hash;

console.log("Public Key Hash:", pubKeyHash);

const datum = Data.to(new Constr(0, [pubKeyHash]));
const redeemer = Data.to(new Constr(0, [fromText("Hello, World!")]));

const spendingValidator = {
  type: "PlutusV3",
  script:
    "59011d0100003232323232323225333002323232323253330073370e900118041baa0011323232533300a3370e900018059baa005132533300e0011613253333330120011616161613253330103012003132533300e3370e900018079baa005132533300f002100114a06644646600200200644a66602a00229404c94ccc04ccdc79bae301700200414a2266006006002602e0026eb0c048c04cc04cc04cc04cc04cc04cc04cc04cc040dd50059bae301230103754602460206ea801458cdc79bae3011300f375401091010d48656c6c6f2c20576f726c64210016375c002601e00260186ea801458c034c038008c030004c024dd50008b1805180580118048009804801180380098021baa00114984d9595cd2ab9d5573caae7d5d0aba25749", // CBOR format from plutus.json
};

const DatumSchema = Data.Object({
  owner: Data.Bytes(),
});
// Removed TypeScript type alias, only keep DatumType as the schema object
const DatumType = DatumSchema;

const scriptAddress = await validatorToAddress("Preprod", spendingValidator);

console.log("Script address:", scriptAddress);

let lockFund = async () => {
  const tx = await lucid
    .newTx()
    .pay.ToContract(
      scriptAddress,
      { kind: "inline", value: datum },
      { lovelace: 10_000_000n }
    )
    .complete();

  const signedTx = await tx.sign.withWallet().complete();

  const txHash = await signedTx.submit();
  console.log("Transaction submitted successfully:", txHash);
};

let spendFund = async (publicKeyHash, spend_val) => {
  // Find the UTxO we want to spend
  const allUTxOs = await lucid.utxosAt(scriptAddress);
  const ownerUTxO = allUTxOs.find((utxo) => {
    if (utxo.datum) {
      const datum = Data.from(utxo.datum, DatumType);
      return datum.owner === publicKeyHash;
    }
  });

  console.log("Owner UTxO:", ownerUTxO);

  if (!ownerUTxO) {
    console.error("No UTxO found for the owner.");
    return;
  }

  // Spend script UTxO
  const tx = await lucid
    .newTx()
    .collectFrom([ownerUTxO], redeemer) // Provide the redeemer argument
    .attach.SpendingValidator(spend_val) // Attach validator
    .addSigner(address) // Add the public key hash as a signer
    .complete();

  const signedTx = await tx.sign.withWallet().complete();

  const txHash = await signedTx.submit();
  console.log("Transaction submitted successfully:", txHash);
};

// lockFund();
spendFund(pubKeyHash, spendingValidator);
