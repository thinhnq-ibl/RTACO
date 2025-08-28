import {
  Lucid,
  Blockfrost,
  Data,
  Constr,
  fromText,
} from "@evolution-sdk/lucid";

import { getAddressDetails, validatorToAddress, mintingPolicyToId, toUnit } from "@evolution-sdk/utils";
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
const validator = validators.find((v) => v.title.includes("iith.iith.mint")); // Assuming you want to use the first validator
const mintValidator = {
  type: "PlutusV3",
  script: validator.compiledCode, // CBOR format from plutus.json
};

const scriptAddress = await validatorToAddress("Preprod", mintValidator);
const policy_id = await mintingPolicyToId(mintValidator);
const mint_asset_unit = toUnit(policy_id, fromText("MyToken"));

let mint = async () => {
  console.log("Minting...");
  const oracle_datum = Data.to(new Constr(1, [
    ])
  );
  const redeemer = Data.to(new Constr(0, []));
  const tx = await lucid
    .newTx()
    .attach.MintingPolicy(mintValidator)
    .mintAssets({ [mint_asset_unit]: 1n }, redeemer)
    .pay.ToContract(
      scriptAddress,
      { kind: "inline", value: oracle_datum },
      { [mint_asset_unit]: 1n }
    )
    .complete();

  const signedTx = await tx.sign.withWallet().complete();

  const txHash = await signedTx.submit();
  await lucid.awaitTx(txHash);
  console.log("Transaction submitted successfully:", txHash);
  // 14d4e1087a0780315ce3447384ef4386f81b3e06a41536d2f8da3a6c5981a573
  return txHash;
};

mint();