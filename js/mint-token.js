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

let start = async () => {
  const py_result = await runPythonScript();
  // console.log("Python script result:", py_result.issue_proof[4]);
  const oracle_datum = Data.to(new Constr(0, [
      0n,
      py_result.issue_proof[4]
    ])
  );
  let include_indexes_bignum = [];
  for (let i = 0; i < py_result.include_indexes.length; i++) {
    let include_indexes_bignum_item = []
    for (let j = 0; j < py_result.include_indexes[i].length; j++) {
      include_indexes_bignum_item.push(BigInt(py_result.include_indexes[i][j]));
    }
    include_indexes_bignum.push(include_indexes_bignum_item);
  }

  let open_proof_3 = []
  for (let i = 0; i < py_result.open_proof[2].length; i++) {
    open_proof_3.push(BigInt(py_result.open_proof[2][i]));
  }

  let issue_proof_2 = []
  for (let i = 0; i < py_result.issue_proof[2].length; i++) {
    issue_proof_2.push(BigInt(py_result.issue_proof[2][i]));
  }

  let issue_proof_3 = []
  for (let i = 0; i < py_result.issue_proof[3].length; i++) {
    let issue_proof_3_item = []
    for (let j = 0; j < py_result.issue_proof[3][i].length; j++) {
      issue_proof_3_item.push(BigInt(py_result.issue_proof[3][i][j]));
    }
    issue_proof_3.push(issue_proof_3_item);
  }

  let vcerts = []
  for (let i = 0; i < py_result.list_vcert.length; i++) {
    vcerts.push(
      new Constr(0, [
        py_result.list_vcert[i][0],
        new Constr(0, [
          BigInt(py_result.list_vcert[i][1][0]),
          BigInt(py_result.list_vcert[i][1][1]),
          py_result.list_vcert[i][1][2]
        ])
      ])
    )
  }

  const datum = Data.to(new Constr(0, [
      1n,
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
  ));

  const blind_sign_1_datum = Data.to(new Constr(0, [py_result.blind_sig1]));
  const blind_sign_2_datum = Data.to(new Constr(0, [py_result.blind_sig2]));

  const verify_redeemer = Data.to(new Constr(2, [
    new Constr(0, [
      py_result.theta[0],
      py_result.theta[1],
      py_result.theta[2],
      new Constr(0, [
        BigInt(py_result.theta[3][0]),
        py_result.theta[3][1].map(x => BigInt(x)),
        BigInt(py_result.theta[3][2]),
      ])
    ]),
    py_result.aggr,
    py_result.aggr_vk[0],
    py_result.theta[4],
    py_result.aggr_vk[1],
    py_result.aggr_vk[2].map(x => BigInt(x)),
    BigInt(py_result.aggr_vk[3]),
    py_result.hs_compressed
  ]));
  // console.log("Datum:", py_result.commits_compressed);
  return { datum, oracle_datum, blind_sign_1_datum, blind_sign_2_datum, verify_redeemer }
}

let oracle = async () => {
  console.log("Oracle...");
  const { datum, oracle_datum, blind_sign_1_datum, blind_sign_2_datum, verify_redeemer } = await start();
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

let mintReq = async (tx_oracle_id, tx_oracle_index) => {
  console.log("Minting req ...");
  const { datum, oracle_datum, blind_sign_1_datum, blind_sign_2_datum, verify_redeemer } = await start();
  let utxos = await lucid.utxosByOutRef([{ txHash: tx_oracle_id, outputIndex: tx_oracle_index }]);
  if(utxos.length === 0) {
    console.error("No UTxOs found");
    return;
  }

  const redeemer = Data.to(new Constr(0, []));
  const tx = await lucid
    .newTx()
    .readFrom(utxos)
    .attach.MintingPolicy(mintValidator)
    .mintAssets({ [mint_asset_unit]: 1n }, redeemer)
    .pay.ToContract(
      scriptAddress,
      { kind: "inline", value: datum },
      { [mint_asset_unit]: 1n, lovelace: 5_000_000n }
    )
    .complete();

  const signedTx = await tx.sign.withWallet().complete();

  const txHash = await signedTx.submit();
  await lucid.awaitTx(txHash);
  console.log("Transaction submitted successfully:", txHash);
  return txHash;
};

let mintBlindSign = async (tx_mint_req_id, tx_mint_req_index, id) => {
  const { datum, oracle_datum, blind_sign_1_datum, blind_sign_2_datum, verify_redeemer } = await start();
  console.log("Minting blind sign ...");
  let utxos = await lucid.utxosByOutRef([{ txHash: tx_mint_req_id, outputIndex: tx_mint_req_index }]);
  if(utxos.length === 0) {
    console.error("No UTxOs found");
    return;
  }

  // console.log(utxos[0].datum)

  const redeemer = Data.to(new Constr(1, []));
  const tx = await lucid
    .newTx()
    .readFrom(utxos)
    .attach.MintingPolicy(mintValidator)
    .mintAssets({ [mint_asset_unit]: 1n }, redeemer)
    .pay.ToContract(
      scriptAddress,
      { kind: "inline", value: id == 1 ? blind_sign_1_datum : blind_sign_2_datum },
      { [mint_asset_unit]: 1n, lovelace: 5_000_000n }
    )
    .complete();

  const signedTx = await tx.sign.withWallet().complete();

  const txHash = await signedTx.submit();
  await lucid.awaitTx(txHash);
  console.log("Transaction submitted successfully:", txHash);
  // 14d4e1087a0780315ce3447384ef4386f81b3e06a41536d2f8da3a6c5981a573
  return txHash;
};

let get_blind_sign = async (tx_blind_sign_id, tx_blind_sign_index) => {
  let utxos = await lucid.utxosByOutRef([{ txHash: tx_blind_sign_id, outputIndex: tx_blind_sign_index }]);
  if(utxos.length === 0) {
    console.error("No UTxOs found");
    return;
  }
  let utxo = utxos[0];
  let datum_raw = utxo.datum;
  let datum = Data.from(datum_raw);
  console.log("Blind sign datum:", datum.fields[0]);
};

let mintVerify = async (verify_id, verify_index) => {
  console.log("Minting verify ...");
  const { datum, oracle_datum, blind_sign_1_datum, blind_sign_2_datum, verify_redeemer } = await start();

  const redeemer = verify_redeemer 
  const tx = await lucid
    .newTx()
    .attach.MintingPolicy(mintValidator)
    .mintAssets({ [mint_asset_unit]: 1n }, redeemer)
    .pay.ToContract(
      scriptAddress,
      null,
      { [mint_asset_unit]: 1n, lovelace: 5_000_000n }
    )
    .complete();

  const signedTx = await tx.sign.withWallet().complete();

  const txHash = await signedTx.submit();
  await lucid.awaitTx(txHash);
  console.log("Transaction submitted successfully:", txHash);
  return txHash;
}

// oracle();
let oracle_tx = "8e67aa880317a25cdc134ef1844f25e0dd220cd681e71302247cfe8628e0a4c7"
mintReq(oracle_tx, 0);
let mint_req_tx = "eab0c5269e3375f0f69de68cd794775e81697b2d739f4956ed6148b1bf198587"
// mintBlindSign(mint_req_tx, 0, 1);
let blind_sig1 = "8738bcb2020363b371202717f26ed237676069f4d5154148b587583cb8d8bde9";
let blind_sig2 = "8d972a05b4e1a71332513b29b2cc9ea8c7d754fe31f292b91690d66e2c4b1e0c";
// get_blind_sign(blind_sig1, 0);
// get_blind_sign(blind_sig2, 0);

// mintVerify();