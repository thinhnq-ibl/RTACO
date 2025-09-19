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

const createUser = async (db, user) => {
  if (db.users.find((u) => u.email === user.email)) {
    console.log("User already exists:", user.email);
    return;
  }
  let data = await runPythonScript("../py/user.py", ["genRandom"]);
  console.log("Generated msk:", data.msk);
  db.users.push({ ...user, msk: data.msk });
  fs.writeFileSync("db.json", JSON.stringify(db, null, 2));
  console.log("User created:", user);
};

// createUser(db, {
//   id: db.users.length + 1,
//   name: "Justin",
//   dob: "2000-01-01",
//   email: "newuser@example.com",
//   organization: "UCLA",
//   salary: 100000,
// });

const createIdentityCertificate = async (db, userEmail, name) => {
  const user = db.users.find((u) => u.email === userEmail);
  if (!user) {
    console.log("User not found:", userEmail);
    return;
  }
  let data = await runPythonScript("../py/user.py", [
    "genPreCert",
    user.msk,
    JSON.stringify(db.schemas.find((s) => s.name === name).params),
    JSON.stringify([user.name, user.dob]),
    JSON.stringify([1, 3]), // encode_str
    JSON.stringify([]),
    JSON.stringify([]),
    JSON.stringify([]), // pre_encoded_attribute
    JSON.stringify([]),
    JSON.stringify([]),
  ]);
  let id = db.precerts.filter((c) => c.user_id === user.id);
  let precert_obj = {
    id: id.length > 0 ? id.length + 1 : 1,
    user_id: user.id,
    title: "Identity Certificate",
    cert: {
      r: data.r,
      commit: data.commit,
      zkpok_c: data.zkpok_c,
      zkpok_totalrm: data.zkpok_totalrm,
    },
  };
  db.precerts.push(precert_obj);
  fs.writeFileSync("db.json", JSON.stringify(db, null, 2));
  console.log("Pre-cert created:", precert_obj);
};

const createIncomeCertificate = async (db, userEmail, name) => {
  const user = db.users.find((u) => u.email === userEmail);
  if (!user) {
    console.log("User not found:", userEmail);
    return;
  }
  const identityCert = db.vcerts.find(
    (x) => x.user_id == user.id && x.title == "Identity Certificate"
  );

  const identityPreCert = db.precerts.find(
    (x) => x.user_id == user.id && x.title == "Identity Certificate"
  );

  let data = await runPythonScript("../py/user.py", [
    "genPreCert",
    user.msk,
    JSON.stringify(db.schemas.find((s) => s.name === name).params),
    JSON.stringify([user.organization, user.salary]),
    JSON.stringify([1, 2]), // encode_str
    JSON.stringify([
      db.schemas.find((s) => s.name === "Identity Certificate").params,
    ]),
    JSON.stringify([identityCert.vcert.attrs]),
    JSON.stringify([identityCert.vcert.encode_attrs]), // pre_encoded_attribute
    JSON.stringify([identityCert.vcert.commit]),
    JSON.stringify([
      [
        identityCert.vcert.sign_r,
        identityCert.vcert.sign_s,
        identityCert.vcert.sign_point,
      ],
    ]),
    JSON.stringify([identityPreCert.cert.r]),
  ]);
  let id = db.precerts.filter((c) => c.user_id === user.id);
  let precert_obj = {
    id: id.length > 0 ? id.length + 1 : 1,
    user_id: user.id,
    title: "Income Certificate",
    cert: {
      commit: data.commit,
      zkpok_c: data.zkpok_c,
      zkpok_totalrm: data.zkpok_totalrm,
    },
  };
  db.precerts.push(precert_obj);
  fs.writeFileSync("db.json", JSON.stringify(db, null, 2));
  console.log("Pre-cert created:", precert_obj);
};

// createIdentityCertificate(db, "newuser@example.com", "Identity Certificate");
// createIncomeCertificate(db, "newuser@example.com", "Income Certificate");

const createCredentialRequest = async () => {
   console.log("Minting req ...");
    
    const datum = [
      new Constr(1, []),
      new Constr(0, [
        BigInt(py_result.issue_proof[0]),
        BigInt(py_result.issue_proof[1]),
        issue_proof_2,
        issue_proof_3,
        py_result.issue_proof[4]
      ]),
      new Constr(0, [
        py_result.open_proof[0],
        py_result.open_proof[1],
        open_proof_3
      ]),
      vcerts,
      py_result.cm_compressed,
      py_result.hs_compressed,
      include_indexes_bignum,
      py_result.combine_hs_compressed,
      py_result.commits_compressed,
      py_result.combine_commits_compressed
    ]
    
    let utxos = await lucid.utxosByOutRef([{ txHash: tx_oracle_id, outputIndex: tx_oracle_index }]);
    if(utxos.length === 0) {
      console.error("No UTxOs found");
      return;
    }
  
    const mint_datum = Data.to(new Constr(0, [
      ...datum,
      utxos[0].txHash, 
      BigInt(utxos[0].outputIndex),
    ]));
  
    // console.log("Mint datum:", mint_datum);
  
    const redeemer = Data.to(new Constr(0, []));
    const tx = await lucid
      .newTx()
      .readFrom(utxos)
      .attach.MintingPolicy(mintValidator)
      .mintAssets({ [mint_asset_unit]: 1n }, redeemer)
      .pay.ToContract(
        scriptAddress,
        { kind: "inline", value: mint_datum },
        { [mint_asset_unit]: 1n, lovelace: 5_000_000n }
      )
      .complete();
  
    const signedTx = await tx.sign.withWallet().complete();
  
    const txHash = await signedTx.submit();
    await lucid.awaitTx(txHash);
    console.log("Transaction submitted successfully:", txHash);
    return txHash;
};
