//// This module implements operations for BLS12-381 signatures.
////
//// The module provides functions for verifying an aggregate BLS signature for multiple public keys and messages.
//// The verification procedure follows the fast aggregate signature verification method described in [this Ethereum Research post](https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407).
////
//// The module assumes that the public keys and messages are provided as byte arrays, and it uses the [aiken/prelude/builtin](https://aiken-lang.github.io/prelude/aiken/builtin.html) module for the underlying cryptographic operations.

use aiken/builtin.{
  bls12_381_final_verify, bls12_381_g1_add, bls12_381_g1_compress,
  bls12_381_g1_scalar_mul, bls12_381_g1_uncompress, bls12_381_g2_add,
  bls12_381_g2_compress, bls12_381_g2_hash_to_group, bls12_381_g2_scalar_mul,
  bls12_381_g2_uncompress, bls12_381_miller_loop,
  bls12_381_mul_miller_loop_result, bytearray_to_integer,
}
use aiken/collection/list.{foldl, length}
use aiken/crypto/bls12_381/g1 as g1
use aiken/crypto/bls12_381/g2 as g2
use aiken/crypto/bls12_381/scalar as scalar

/// DSTs - The domain separation tags for the hash-to-curve function.
pub const dst_basic_G1 = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"

pub const dst_basic_G2 = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"

/// Converts a secret key (sk) to a corresponding public key (PK) using the BLS12-381 elliptic curve.
/// Computes the public key by multiplying the secret key with the generator point.
///
/// Parameters:
/// * `sk`: ByteArray - The secret key of the user.
///
/// Returns:
/// ByteArray - The compressed public key corresponding to the secret key.
pub fn skToPk(sk: ByteArray) -> G1Element {
  let s = bytearray_to_integer(True, sk)
  bls12_381_g1_scalar_mul(s, g1.generator)
}

// This function performs the pairing operation using the Miller loop algorithm on two elements,
// one from G1 and one from G2.
pub fn group_pairing(g1: G1Element, g2: G2Element) {
  bls12_381_miller_loop(g1, g2)
}

/// Generates a BLS12_381 signature for a given message using the private key.
/// The function hashes the message to a point on the G2 curve, converts the private key to a scalar,
/// and multiplies the scalar with the point. The resulting point is then compressed to obtain the signature.
///
/// Parameters:
/// * `sk`: ByteArray - The private key of the user.
/// * `message`: ByteArray - The message to be signed.
///
/// Returns:
/// G2Element - The compressed BLS12_381 signature for the given message.
pub fn sign(sk: ByteArray, message: ByteArray) -> G2Element {
  let s = bytearray_to_integer(True, sk)

  let hash = bls12_381_g2_hash_to_group(message, dst_basic_G2)
  bls12_381_g2_scalar_mul(s, hash)
}

/// Verifies a BLS12_381 signature for a given message and public key.
/// The function converts the signature to a point, hashes the message to a point on the G1 curve,
/// and computes two pairing values to check if they are equal, determining the signature's validity.
///
/// Parameters:
/// * `pk`: ByteArray - The public key of the signer.
/// * `message`: ByteArray - The message to be verified.
/// * `signature`: ByteArray - The BLS12_381 signature to be verified.
///
/// Returns:
/// bool - `true` if the signature is valid, `false` otherwise.
pub fn verify(pk: G1Element, message: ByteArray, signature: G2Element) -> Bool {
  // Hash the message to a point.
  let q = bls12_381_g2_hash_to_group(message, dst_basic_G2)

  // Check if the pairing of the public key and hashed message is equal to the pairing of the generator and signature.
  let c1 = group_pairing(pk, q)
  let c2 = group_pairing(g1.generator, signature)
  bls12_381_final_verify(c1, c2)
}

pub fn blind_message(message: ByteArray, blind_factor: ByteArray) -> G2Element {
  let r = bytearray_to_integer(True, blind_factor)
  // Hash the message to a point
  let h = bls12_381_g2_hash_to_group(message, dst_basic_G2)
  // Compute blinded message point
  bls12_381_g2_scalar_mul(r, h)
}

pub fn blind_sign(sk: ByteArray, blinded_msg: G2Element) -> G2Element {
  let s = bytearray_to_integer(True, sk)

  // Simple blind signature: s = sk * blinded_msg
  bls12_381_g2_scalar_mul(s, blinded_msg)
}

pub fn unblind_signature(
  blind_sig: G2Element,
  blind_factor: ByteArray,
) -> G2Element {
  let s = bytearray_to_integer(True, blind_factor)
  expect Some(scalar_s) = scalar.new(s)
  expect Some(scalar_one) = scalar.new(1)
  // Compute r^-1 mod curve_order
  let scalar_r_inv = scalar.div(scalar_one, scalar_s)
  expect Some(r_inv_int) = scalar_r_inv
  // Unblind the signature
  let r_inv = scalar.to_int(r_inv_int)
  bls12_381_g2_scalar_mul(r_inv, blind_sig)
}

/// Test
const sk1 = #"6284b61a07c6bd3e632beb6294dfc780ad04489c8c31b73b0aef73608f3d1231"

const pk1 =
  #"82cbde4e4fc6a56b6f84f2ceabb191ed7d4402835f8caa1e166554e7d7a925fe2cab59f113b78c91a4b37001d2a9c75f"

const msg1 = #"000001"

const sg1 =
  #"b558aab6dd33d777973a19fb34c3a1c636315a039a0e9ea7da4f78fe5d4470a0b4ec3d2b3324b81e5e759875c224c8ec0e1ce698faa40426165f799cb358d965b8e8dc82ee01f702008e68a0309a8261bb5e348f349521b26eed6961c22de869"

test skToPk_1() {
  let pk2 = skToPk(sk1)
  expect pk1 == g1.compress(pk2)
}

test sign_1() {
  let sig = sign(sk1, msg1)
  expect sg1 == g2.compress(sig)
}

test verify_1() {
  let sig = g2.decompress(sg1)
  let pk = g1.decompress(pk1)
  expect verify(pk, msg1, sig)
}
