import {
  Lucid,
  Blockfrost,
  Data,
  Constr,
  fromText,
} from "@evolution-sdk/lucid";

import { getAddressDetails, validatorToAddress } from "@evolution-sdk/utils";
import plutusScript from "../plutus.json"  with { type: 'json' };// Assuming you have a JSON file with the Plutus script
import { runPythonScript } from "./run_py.js";

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

const validators = plutusScript.validators;
const validator = validators.find((v) => v.title.includes("iith.iith.spend")); // Assuming you want to use the first validator

// console.log("validator:", validator);

const spendingValidator = {
  type: "PlutusV3",
  script: validator.compiledCode, // CBOR format from plutus.json
};

const Proof = {
  c: Data.Integer(),
  rm: Data.Array(Data.Integer()),
  rt: Data.Integer(),
};

const Theta = {
  kappa: Data.Array(Data.Bytes()),
  nu: Data.Bytes(),
  sigma: Data.Array(Data.Bytes()),
  proof: Proof,
}

const VerifyCredDatum = Data.Object({
  theta: Theta,
  aggr: Data.Bytes(),
  alpha: Data.Array(Data.Bytes()),
  aw: Data.Array(Data.Bytes()),
  beta: Data.Array(Data.Array(Data.Bytes())),
  disclose_attr: Data.Array(Data.Integer()),
  timestamp: Data.Integer(),
  hs_compressed: Data.Array(Data.Bytes()),
});

let start = async () => {
  const py_result = await runPythonScript();
  console.log("Python script result:", py_result);
  const oracle_datum = Data.to(new Constr(0, [
      py_result.issue_proof[4]
    ])
  );
  
  const datum = Data.to(new Constr(0, [
    new Constr(0, [
      py_result.theta[0],
      py_result.theta[1],
      py_result.theta[2],
      new Constr(0, [
        BigInt(py_result.theta[3][0]),
        [
          BigInt(py_result.theta[3][1][0]),
          BigInt(py_result.theta[3][1][1]),
        ],
        BigInt(py_result.theta[3][2]),
      ])
    ]),
    py_result.aggr,
    py_result.aggr_vk[0],
    py_result.theta[4],
    py_result.aggr_vk[1],
    py_result.aggr_vk[2],
    BigInt(py_result.aggr_vk[3]),
    py_result.hs_compressed
  ]));
  // console.log("Datum:", py_result.commits_compressed);
  return { datum, oracle_datum}
}

const DatumSchema = VerifyCredDatum

const { datum, oracle_datum } = await start();

// Removed TypeScript type alias, only keep DatumType as the schema object
const DatumType = DatumSchema;

const scriptAddress = await validatorToAddress("Preprod", spendingValidator);

// console.log("Script address:", scriptAddress);

let lockFund = async () => {
  console.log("Locking funds...");
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
  // 14d4e1087a0780315ce3447384ef4386f81b3e06a41536d2f8da3a6c5981a573
};

let spendFund = async (publicKeyHash, spend_val, tx_id) => {
  console.log("Spending funds...");
  // Find the UTxO we want to spend
  const allUTxOs = await lucid.utxosAt(scriptAddress);
  const ownerUTxO = allUTxOs.find((utxo) => {
    return utxo.txHash == tx_id
  });

  console.log("Owner UTxO:", ownerUTxO);

  if (!ownerUTxO) {
    console.error("No UTxO found for the owner.");
    return;
  }

  const redeemer = Data.to(new Constr(1, [])); // Redeemer for the script, can be empty or contain specific data

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

//let lock_tx = await lockFund();
let lock_tx_id = "2f19564b827845d2ee31f543ec5deae16105f520b071464a6a22d26854c32091"
spendFund(pubKeyHash, spendingValidator, lock_tx_id);
