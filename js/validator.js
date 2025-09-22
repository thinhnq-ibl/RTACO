import { runPythonScript } from "./run_py.js";
import fs from "fs";

import {
  Lucid,
  Blockfrost,
  Data,
  Constr,
  fromText,
} from "@evolution-sdk/lucid";

import { getAddressDetails, validatorToAddress, mintingPolicyToId, toUnit } from "@evolution-sdk/utils";
import plutusScript from "../plutus.json"  with { type: 'json' };// Assuming you have a JSON file with the Plutus script

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
const validator = validators.find((v) => v.title.includes("iith.iith.mint")); // Assuming you want to use the first validator
const mintValidator = {
  type: "PlutusV3",
  script: validator.compiledCode, // CBOR format from plutus.json
};

const scriptAddress = await validatorToAddress("Preprod", mintValidator);
const policy_id = await mintingPolicyToId(mintValidator);
const mint_asset_unit = toUnit(policy_id, fromText("MyToken"));

const data = fs.readFileSync("db.json");
const db = JSON.parse(data);

const createValidator = async (db) => {
  let data = await runPythonScript("../py/validator.py", [
    "genValidator",
    JSON.stringify(2),
    JSON.stringify("Loan Credential"),
  ]);
  console.log("Generated msk:", data);
  db.validators = data;
  fs.writeFileSync("db.json", JSON.stringify(db, null, 2));
  //   console.log("User created:", user);
};

// createValidator(db);

let createOracle = async (db) => {
  console.log("Oracle...");
  const pks = db.schemas.map(x => x.pk)
  const oracle_datum = Data.to(new Constr(0, [
      new Constr(0, []),
      pks
    ])
  );
  const tx = await lucid
    .newTx()
    .pay.ToContract(
      scriptAddress,
      { kind: "inline", value: oracle_datum },
      { lovelace: 5_000_000n }
    )
    .complete();

  const signedTx = await tx.sign.withWallet().complete();

  const txHash = await signedTx.submit();
  await lucid.awaitTx(txHash);
  console.log("Transaction submitted successfully:", txHash);
  // 14d4e1087a0780315ce3447384ef4386f81b3e06a41536d2f8da3a6c5981a573
  return txHash;
};

// createOracle(db)
// f1fdffd67a856346490ff6c5a9131c6b9567774cf858a3941ebc23392f87f6fd