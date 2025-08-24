import {
  Lucid,
  Blockfrost,
  Data,
  Constr,
  fromText,
} from "@evolution-sdk/lucid";

import { getAddressDetails, validatorToAddress } from "@evolution-sdk/utils";
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

const DatumSchema = VerifyCredDatum

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
  [
    "a277357a6c44f5080f27ce2964d0b0e7c3e590d0e48dc0e032436ae15cbd435082e2266baed48398432ab43446337c21",
    "0f654ac4e8d02c6aefa7ebe4dac7691c4d2fc84cf9b349c9cfac1e34c1be67e1728662697bdd59ba11df76880a588194",
  ],
  [
    "861a318ec595e5b1b366ba6066558bf89cd2a93f5885b678486ffa58ccf9beea1f129e7bac57b1ea13cb9a2bc4d58eb1",
    "0a92d4217f1e2df21207347602d9e0f9edbaf3ee2f7b148bee82e7e3448b82a96810196a751570cabf559e73ed26f376",
  ],
  [
    [
      "87aa5e894fa26828d65a083287a8a271f1217ab4b681f9653d0f85c073532be85e57b8ebe394ae4bfe1dcae7b8745ac2",
      "15dfc642cc4c9cb1703cd25806ef7aa8dfdcd2d36a7c0b8e4165dfa283abc2d386b794f34a32014e9820ef41681ef7f2",
    ],
    [
      "a69c24fdb1f77e1b0b1656d642f2205f2aff2b68fe2a8af6a8f1c77b5f743f31c639d11521d35f344fb52cd847fafbb2",
      "106c7075a1d888351ca6b62a8adf67d76b56479076d8dcb1642019ebf8a69680bf4c2f0f909ac84ecff05dec923bd8ba",
    ],
  ],
  [],
  1753846862n,
  [
    "a090cfe9261fdcfbe1b0b3f74256e57f6a5bdd98c13b0e09f9484838b02239a0ab8b883b7910585c13918f995eb8df89",
    "865341b6a4affbe3b795d2d3c71781ad7267849fe2b24e728e13524d60d08e5a1681344b20268ea337d2fa2c1c3bbd7c",
  ]
]));

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

// lockFund();
spendFund(pubKeyHash, spendingValidator, "bb586cc2344b78765f54cc619b36278914ff122ae1fbeebcf67381f63628ead1");
