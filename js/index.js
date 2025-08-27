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
  const datum = Data.to(new Constr(0, [
      new Constr(0, [
        42535636952854378490874194418722333779152010990979182213475440387396116429547n,
        40675462214123865742431951389911046237865684117786381568714250885257348136441n,
        [
          47925282862226222643927521835608820926632670018838597296086614014727602246558n,
          21687859965734279473419411257190997575311278370788120793865541862802550871605n,
        ],
        [
            [
                50308106295266800020532960251996643677383528606831312922664123595083067330785n,
                5095311348487787861645372845191969718727204196912877257125842030966424005608n,
                24215618229245167673429987719866984434968409701328374910407976599467102132405n,
                23117088388493107445729512963030794110283280127530426202939187508228779289686n,
            ],
            [
                50308106295266800020532960251996643677383528606831312922664123595083067330785n,
                40928904529511035926773476820862854867207669516607935231354640227867095612728n,
                25499875010848260697670552620696378616666315278639900420553745755017069746308n,
            ],
            []
        ],
        [
            "a97b2135da7799823236baea87402c5cc00e3a61c99e9abf7c2d9c0c29d1c50fd5753e3076c5e3da091c861199ee72b7",
            "b51cc7408bc47ad537c29fef899a73b784de41c2063d5aac5248623f3db3dd4131e1cd9af902d49b28bc38819ffb48eb"
        ]
          ]),
          new Constr(0, [
          [
            [
              "b7d202145af60c01a1294e20a824ec0ff5a8bb3c8960a0862714fdad6f1d72afeb38c2ef9ede0efa80f4bc530e361c05",
              "12f07e97e697747ff1732948b6a9588f0502bc78d5ebcfbc0ccbd599f12fa73086711a758e32c29ed65671cc75a4b742",
            ],
            [
              "b17404753763b1a7a2c8f3eda805c94e7e5726ca2d8850fcc64e7da63501f228ddbaba2646761505034b41133f106f00",
              "192f783e17209bfbf58196e6a81edf05d5694ea016a559aa8c1ea70a7e6a31320037b88e8f19d125bcadf9120e214fc6",
            ],
            [
              "a9b246d918b61b40990060eed918839eed12404dcd4e8fee55fde61aa5f7f532e6aa46fb89a8558c5997497c130ba1c9",
              "13fb095a31ee0b02fb61b2e991027909810cd6140056cd47dc6ab5a8f8f9cdd48bf71683fe6315854992041cc5f32426",
            ],
          ],
          [
            [
              "b21b44aa690efa4366df2bab175f0f29dd58f3f05848199f1870b9a857a20cc0de9d862a9e773f6c0733b7582a8d3dec",
              "0838b6c4c31121fc67a63f0a56f607cdbd9fbf6de1fbc81f89b2a0a2e967facc671c9e8bdf5341c5ab1b1b36e4a0618f",
            ],
            [
              "a24e10a1f880d42e061513da1d224d009139b2aa1d52b7cc8b603c316a6a43f2d1a9862cf95cd59bf8aaf7e9fe5f0ccd",
              "0d24adec785a3adea053b05e3c8a0369f5b95568b2ef8092e4aafaef6d4d5546f43e05133d0624956f9e6264e070b17c",
            ],
            [
              "974932069a948e5776dd4d7928b26840a8188012ced6894a454552ddb6abf2b2dc946e56b8c493f7bec43fe5e69070f7",
              "0a01382b44ed8653af6190c303009f2bf51f60eaa0f171fb3a24274515202d81baf143e4b17e276723a40574449af4e9",
            ],
          ],
              [
                  13804325079850457725627142957951104827873126539730078258784195038440940880392n,
                  11726514466030405860930521000683610778958399959004350468181692188389284878278n,
                  51432526391402064059818130005060767434915237470275281612051755280949532972757n,
              ]
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
          [
              "a090cfe9261fdcfbe1b0b3f74256e57f6a5bdd98c13b0e09f9484838b02239a0ab8b883b7910585c13918f995eb8df89",
              "865341b6a4affbe3b795d2d3c71781ad7267849fe2b24e728e13524d60d08e5a1681344b20268ea337d2fa2c1c3bbd7c"
          ],
          [
              [0n, 0n, 1n, 0n], [0n, 1n, 0n]
          ],
          [
            [
              "afcccdf181372ae095c90ab978b2644ea70a26a9882f958f4b444198526a08df0ac0d2f3a22def8fe9bc90dd6c026fc3",
              "a96a8434d5128874888977d279af969e6de98ff9d4abd5a640dd8ab425db07c0d7fa89c49681b7dc39f14de669cd2482",
              "a8bd2ff8845790d820c3c180fc29cf57545cf5d37db7eb06cf0a0d4ae2f8fa32bcce4fe84828ab57126658c40402761f",
            ],
            [
              "86fa463aeca16b8a4b40983734410be0108e1d708fde32ca51eae6b971f6cd24555b7372a7a84238ab1941205a8b2c4d",
              "9728604cdc4edd3950b0b9c815a7f08cdd9bf2983b9a049b79c1150036ae0c9b036c3000b291c805942d2bfc741cc5f3",
            ],
          ],
          [
              "83a30f27817b9a06550b8d7f81b5594281f35259660f30c9ebf4b09a7a249c644ab2918432e90b0d0c2887f25f14aceb",
              "b0b3013fd69e7d201c862e9e4e5308ba7d4d39a2a602c384660a0cfbddb09dc5c167a2d07ee02f8e73b9a996012b5992",
      ],
      [
        "a75320f826a216c87da892bfc8aaacd2a75f5ccdfa62b72de3491b0bf079201a2def1fc9f18234df324976fdaf267870",
        "a3324843cb50de5ba1dc8202d2f122a079857340727e63ad1227c3c9068acbd6039d452a6cf8b49405bd895c528582f3",
      ]
    ]
  ));
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

let tx_oracle = await oracle()
let lock_tx = await lockFund();
await spendFund(pubKeyHash, spendingValidator, lock_tx, tx_oracle, 0);
