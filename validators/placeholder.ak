use aiken/builtin
use aiken/crypto.{sha2_256}
use aiken/crypto/bls12_381/g1 as g1
use aiken/crypto/bls12_381/g2 as g2
use aiken/crypto/bls12_381/scalar.{new}
use aiken/primitive/bytearray
use cardano/address.{Credential}
use cardano/assets.{PolicyId}
use cardano/certificate.{Certificate}
use cardano/governance.{ProposalProcedure, Voter}
use cardano/transaction.{OutputReference, Transaction}

// test test_G1() {
//   // This is a test function to demonstrate the use of the `G1` type.
//   // It creates a new `G1` element and performs some operations on it.
//   let g1_element = g1.generator
//   // compress(g1_element) == #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
//   // decompress(
//   //   #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
//   // ) == g1_element
//   expect Some(x) = new(2)
//   trace g1.decompress(
//     #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
//   )
//   g1.equal(g1.add(g1_element, g1_element), g1.scale(g1_element, x)) == True
// }

fn gen_pubkey(priv_key: Int) -> G2Element {
  // This function generates a public key from a given private key.
  // It uses the `scale` function from the `g2` module to perform the operation.
  expect Some(x) = new(priv_key)
  g2.scale(g2.generator, x)
}

// test gen_pubkey_1() {
//   // This is a test function to demonstrate the use of the `gen_pubkey` function.
//   // It generates a public key from a given private key and verifies its correctness.
//   let priv_key = 988888888
//   let pubkey = gen_pubkey(priv_key)
//   expect
//     pubkey == g2.decompress(
//       #"94329fc3fdf14a35bb328ac04298597890cad71a4b5034e154b44974883b5633c1ea29cf00a654b617aa9aea174e96f601d0b6083604e73343f7193a842ef3911bd7227c70736290bdb2306b104ee7145643d1fe6c1cbba0ceae689786a14b3d",
//     )
// }

type UserData {
  name: String,
  dob: String,
}

type MyCert {
  user_data: UserData,
  signature: G1Element,
  issuer_pk: G2Element,
}

fn create_certificate(priv_key: Int, user_data: UserData) -> MyCert {
  // Create a verifiable certificate for user data
  // user_data should contain 'name' and 'dob' fields
  let data_hash =
    g1.hash_to_group(
      bytearray.concat(
        bytearray.from_string(user_data.name),
        bytearray.from_string(user_data.dob),
      ),
      "user_data",
    )
  // Create signature (certificate)
  expect Some(issuer_sk) = new(priv_key)
  let signature = g1.scale(data_hash, issuer_sk)
  MyCert { user_data, signature, issuer_pk: g2.scale(g2.generator, issuer_sk) }
}

// test create_certificate_1() {
//   // This is a test function to demonstrate the use of the `create_certificate` function.
//   // It creates a certificate for user data and verifies its correctness.
//   let priv_key = 988888888
//   let user_data = UserData { name: @"Alice", dob: @"1990-01-01" }
//   let cert = create_certificate(priv_key, user_data)
//   trace @"Certificate sig: ": cert.signature
//   expect
//     cert.signature == g1.decompress(
//       #"95ead086ae9eb126e453034cf24b64b3249c31b39946e77a7cf90bfb7cfa3c73c2f29249048a7d2f2559eecd4c87e872",
//     )
// }

fn verify_certificate(certificate: MyCert) -> Bool {
  //  Verify the certificate's authenticity
  // Extract components
  let user_data = certificate.user_data
  let signature = certificate.signature
  let issuer_pk = certificate.issuer_pk
  // Recompute hash
  let g1_data =
    g1.hash_to_group(
      bytearray.concat(
        bytearray.from_string(user_data.name),
        bytearray.from_string(user_data.dob),
      ),
      "user_data",
    )
  // Verify pairing: e(signature, G2) == e(g1_data, issuer_pk)
  builtin.bls12_381_final_verify(
    builtin.bls12_381_miller_loop(signature, g2.generator),
    builtin.bls12_381_miller_loop(g1_data, issuer_pk),
  )
}

validator placeholder {
  mint(_redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    todo @"mint logic goes here"
  }

  spend(
    _datum: Option<Data>,
    _redeemer: Data,
    _utxo: OutputReference,
    _self: Transaction,
  ) {
    todo @"spend logic goes here"
  }

  withdraw(_redeemer: Data, _account: Credential, _self: Transaction) {
    todo @"withdraw logic goes here"
  }

  publish(_redeemer: Data, _certificate: Certificate, _self: Transaction) {
    todo @"publish logic goes here"
  }

  vote(_redeemer: Data, _voter: Voter, _self: Transaction) {
    todo @"vote logic goes here"
  }

  propose(_redeemer: Data, _proposal: ProposalProcedure, _self: Transaction) {
    todo @"propose logic goes here"
  }

  // // If needs be, remove any of unneeded handlers above, and use:
  //
  // else(_ctx: ScriptContext) {
  //   todo @"fallback logic if none of the other purposes match"
  // }
  //
  // // You will also need an additional import:
  // //
  // // use cardano/script_context.{ScriptContext}
}
