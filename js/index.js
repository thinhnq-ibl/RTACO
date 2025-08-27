import {
  Lucid,
  Blockfrost,
  Data,
  Constr,
  fromText,
} from "@evolution-sdk/lucid";

import { getAddressDetails, validatorToAddress } from "@evolution-sdk/utils";
import plutusScript from "../plutus.json"  with { type: 'json' };// Assuming you have a JSON file with the Plutus script
import { exit } from "process";

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
const spendingValidator = {
  type: "PlutusV3",
  script: validator.compiledCode, // CBOR format from plutus.json
};

const IssueProof = Data.Object({
  c: Data.Integer(),
  rr: Data.Integer(),
  ros: Data.Array(Data.Integer()),
  total_rm: Data.Array(Data.Array(Data.Integer())),
  pubkeys: Data.Array(Data.Bytes()),
});

const OpenProof = Data.Object({
    dw: Data.Array(Data.Array(Data.Bytes())),
    ew: Data.Array(Data.Array(Data.Bytes())),
    c: Data.Array(Data.Integer()),
});

const Sign = Data.Object({
    r: Data.Integer(),
    s: Data.Integer(),
    r_g1: Data.Bytes(),
});

const Vcert = Data.Object({
    commit: Data.Array(Data.Bytes()),
    signature: Sign,
});

const BlindSignDatum = Data.Object({
    iproof: IssueProof,
    open: OpenProof,
    vcerts: Data.Array(Vcert),
    cm_compressed: Data.Bytes(),
    h_compressed: Data.Bytes(),
    hs_compressed: Data.Array(Data.Bytes()),
    include_indexes: Data.Array(Data.Array(Data.Integer())),
    combine_hs_compressed: Data.Array(Data.Array(Data.Bytes())),
    commits_compressed: Data.Array(Data.Bytes()),
    combine_commits_compressed: Data.Array(Data.Bytes()),
});

const DatumSchema = BlindSignDatum

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

  console.log("Index BigNum:",  BigInt(py_result.issue_proof[1]), issue_proof_2, issue_proof_3, open_proof_3, include_indexes_bignum);
  const datum = Data.to(new Constr(0, [
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
      [
        new Constr(0, [
          [
              "075320f826a216c87da892bfc8aaacd2a75f5ccdfa62b72de3491b0bf079201a2def1fc9f18234df324976fdaf267870",
              "112bdf0ec3b461ae5bf50d9d0cde259cfdaa4789a6a7595dc3a37a76d6bc7c11d14cfb7528a60ea753bba5e501af4d5a",
          ],
          new Constr(0, [
            1947564745249895947708144629914312558157305610980073189304752255321217468940983390413315295194393892376039785033790n,
            17355617863143591184525546256817223357573510192270296979117455415910592064385n,
            "aca7513f4288ab39cdb45202f54678d9bd5d815b52295dc7f22b16c7572e13b93d96b6837288a909d801ce61a638f03e"
          ])
        ]),
        new Constr(0, [
          [
            "03324843cb50de5ba1dc8202d2f122a079857340727e63ad1227c3c9068acbd6039d452a6cf8b49405bd895c528582f3",
            "19de1c7c436db928c356fc685aa32832ade4583760476d176f366c0fd5b92d4b93256afd144d2f815abd721d497d2aee",
          ],
          new Constr(0, [
            3924284939951961681834764047095286118299427666162894647982549458393534809915388538121180076697345644595416192308475n,
            30161833219843676097829195363654408677477538928028790969163359605163750361918n,
            "b97f20c47b4d12e53f6cb898067b63532e53c906b200f2638db569a7d50977a7fbb53609e324b65a9934b3d08960d4fb"
          ])
        ])
      ],
      py_result.cm_compressed,
      py_result.hs_compressed,
      include_indexes_bignum,
      py_result.combine_hs_compressed,
      py_result.commits_compressed,
      py_result.combine_commits_compressed
    ]
  ));
  console.log("Datum:", py_result.commits_compressed);
  return { datum, oracle_datum}
}

// Removed TypeScript type alias, only keep DatumType as the schema object
const DatumType = DatumSchema;

const scriptAddress = await validatorToAddress("Preprod", spendingValidator);

// console.log("Script address:", scriptAddress);
const { datum, oracle_datum } = await start();

let oracle = async () => {
  console.log("Oracle...");
  const tx = await lucid
    .newTx()
    .pay.ToContract(
      scriptAddress,
      { kind: "inline", value: oracle_datum },
      { lovelace: 10_000_000n }
    )
    .complete();

  const signedTx = await tx.sign.withWallet().complete();

  const txHash = await signedTx.submit();
  await lucid.awaitTx(txHash);
  console.log("Transaction submitted successfully:", txHash);
  // 14d4e1087a0780315ce3447384ef4386f81b3e06a41536d2f8da3a6c5981a573
  return txHash;
};

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
  await lucid.awaitTx(txHash);
  console.log("Transaction submitted successfully:", txHash);
  // 14d4e1087a0780315ce3447384ef4386f81b3e06a41536d2f8da3a6c5981a573
  return txHash;
};

let spendFund = async (publicKeyHash, spend_val, tx_id, ref_tx, ref_index) => {
  let utxos = await lucid.utxosByOutRef([{ txHash: ref_tx, outputIndex: ref_index }]);
  if(utxos.length === 0) {
    console.error("No UTxOs found");
    return;
  }
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

  const redeemer = Data.to(new Constr(0, [])); // Redeemer for the script, can be empty or contain specific data

  // Spend script UTxO
  const tx = await lucid
    .newTx()
    .collectFrom([ownerUTxO], redeemer) // Provide the redeemer argument
    .readFrom(utxos)
    .attach.SpendingValidator(spend_val) // Attach validator
    .addSigner(address) // Add the public key hash as a signer
    .complete();

  const signedTx = await tx.sign.withWallet().complete();

  const txHash = await signedTx.submit();
  await lucid.awaitTx(txHash);
  console.log("Transaction submitted successfully:", txHash);
  return txHash;
};

// let tx_oracle = await oracle()
let tx_oracle_id = "a577dc82b8cfa625ee0bf24a0511823fdb82881e41a6c8e59c0b38f4520c69c7"
// let lock_tx = await lockFund();
let lock_tx_id = "cacf370f8a2f3cc90758b12d60554e88aa2d0de2eaa7665a946ee95607c90305"
await spendFund(pubKeyHash, spendingValidator, lock_tx_id, tx_oracle_id, 0);
