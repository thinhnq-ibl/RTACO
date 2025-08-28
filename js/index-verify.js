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
  console.log("Python script result:", py_result.issue_proof[4]);
  const oracle_datum = Data.to(new Constr(0, [
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

  // console.log("Index BigNum:",  BigInt(py_result.issue_proof[1]), issue_proof_2, issue_proof_3, open_proof_3, include_indexes_bignum);
  const datum = Data.to(new Constr(0, [
    new Constr(0, [
      [
        "878a8ad400fad9651450254eb59e00d32430106965d2d3c17a7888152249440ff00cfb731c9e70ab05b2b1794fd4f296",
        "0b07b8c368b4f00072bc7e6b9c74723e6fd6ffbe59bb7889da38d51a52e5f6086f3d60033ea8567114f9409f3d230a9b",
      ],
      "a6e229247ef0dea50213e7245216c948d3e8471a32d2a65a6d74e6edf4911bc04bd7165f227cd4358ad0da8f745ab843",
      [
      "a818baa56c6c069f45b09833057480298637af3eb20f2aed46314dff3ecce01d47d35cf27cf57e511b248daaa24245ea",
        "9117e4f0f81c8483d8cd6967ce547e1af18bfe85e0cf59aba25b3c6668b2e3a740e49131a5c7e8bfef4466c3a58e6f28",
      ],
      new Constr(0, [
        43953825675714075024391357470089393824546011683396945525107498247681984930981n,
        [
          33201398774658044924842383368859864201050291569118115993700463891168183954704n,
          1886665901031710547374862922187803698730842134686358055213993339908120500534n,
        ],
        34386718347699404645595550243171262552307584501849354162591548582147168255223n,
      ])
    ]),
    "",
    py_result.aggr_vk[0],
    [
      "861a318ec595e5b1b366ba6066558bf89cd2a93f5885b678486ffa58ccf9beea1f129e7bac57b1ea13cb9a2bc4d58eb1",
      "0a92d4217f1e2df21207347602d9e0f9edbaf3ee2f7b148bee82e7e3448b82a96810196a751570cabf559e73ed26f376",
    ],
    py_result.aggr_vk[1],
    [],
    1753846862n,
    [
      "a090cfe9261fdcfbe1b0b3f74256e57f6a5bdd98c13b0e09f9484838b02239a0ab8b883b7910585c13918f995eb8df89",
      "865341b6a4affbe3b795d2d3c71781ad7267849fe2b24e728e13524d60d08e5a1681344b20268ea337d2fa2c1c3bbd7c",
    ]
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

// let lock_tx = await lockFund();
let lock_tx_id = "efb8369c9fe35dff31010896da4d3041b51f88580e2ba294a77ab41e93ce4770"
spendFund(pubKeyHash, spendingValidator, lock_tx_id);
