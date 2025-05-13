//// This module implements operations for BLS12-381 signatures.
////
//// The module provides functions for verifying an aggregate BLS signature for multiple public keys and messages.
//// The verification procedure follows the fast aggregate signature verification method described in [this Ethereum Research post](https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407).
////
//// The module assumes that the public keys and messages are provided as byte arrays, and it uses the [aiken/prelude/builtin](https://aiken-lang.github.io/prelude/aiken/builtin.html) module for the underlying cryptographic operations.

// https://github.com/ilap/bls/blob/main/lib/bls/core.ak

use aiken/builtin.{
  bls12_381_final_verify, bls12_381_g1_scalar_mul, bls12_381_g2_hash_to_group,
  bls12_381_g2_scalar_mul, bls12_381_miller_loop, bytearray_to_integer,
}
use aiken/collection/list.{head, tail}
use aiken/crypto.{sha2_256}
use aiken/crypto/bls12_381/g1 as g1
use aiken/crypto/bls12_381/g2 as g2
use aiken/crypto/bls12_381/scalar as scalar
use aiken/option.{is_none}
use aiken/primitive/bytearray.{concat}
use aiken/primitive/int.{from_bytearray_big_endian}

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
  trace hash
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

const hash =
  #"b8ee5db274e4ed884d6acae616b1c292004bb3df5c150e7eee66d6aed86ce3481300cdfe037651d9e01af95f539bf63a13d14cbc4ff1c45149ece6777e6c5b2860c0ec14253b9667200ea5bb6c2d11bf1315c552da7a7d60092d7010da158a2f"

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

test blind_sign_1() {
  let blind_factor =
    #"1234567890123456789012345678901234567890123456789012345678901234"
  let blind_sig = blind_sign(sk1, blind_message(msg1, blind_factor))
  let unblind_sig = unblind_signature(blind_sig, blind_factor)
  expect sg1 == g2.compress(unblind_sig)
}

// Calculates the modular inverse of `a` modulo `m` using the Extended Euclidean Algorithm.
// Returns 0 if the inverse does not exist.
fn mod_inverse(a: Int, m: Int) -> Int {
  if m == 1 {
    0
  } else {
    go(a, m, 1, 0, m)
  }
}

fn go(a: Int, m: Int, x: Int, y: Int, m0: Int) -> Int {
  if a <= 1 {
    if x < 0 {
      x + m0
    } else {
      x
    }
  } else {
    let q = a / m
    let t = m
    let r = a % m
    let new_a = t
    let new_m = r
    let new_x = y
    let new_y = x - q * y
    go(new_a, new_m, new_x, new_y, m0)
  }
}

test mod_inverse_works() {
  // 3 * 9 ≡ 1 mod 26
  mod_inverse(3, 26) == 9
}

pub type Sign {
  r: Int,
  s: Int,
  r_g1: G1Element,
}

pub fn do_ecdsa_verify(pk: G1Element, sign: Sign, commit: ByteArray) -> Bool {
  let r = sign.r
  let s = sign.s
  let o = scalar.field_prime
  let digest = sha2_256(commit)
  let int_digest = from_bytearray_big_endian(digest) % o
  let s1 = mod_inverse(s, o)
  let x1 = int_digest * s1 % o
  let x2 = r * s1 % o
  expect Some(x1_) = scalar.new(x1)
  let pt1 = g1.scale(g1.generator, x1_)
  expect Some(x2_) = scalar.new(x2)
  let pt2 = g1.scale(pk, x2_)
  let r_check = g1.add(pt1, pt2)
  g1.equal(sign.r_g1, r_check)
}

test do_ecdsa_verify_test() {
  let pk =
    g1.decompress(
      #"968cc0fcd3879a0b7b1f1f70fe60a7c5ea3aa45fcbb2d4963c5dec7b9efa5ec23be6ebf59f285d904d734afdf2f0147e",
    )
  let sign =
    Sign {
      r: 1405393218543153634611558277146205543651389828460482046569307751654236783901042705626443752376987448075822652265738,
      s: 38202479084295088188067894688129388712852808125955621239765113527621075572534,
      r_g1: g1.decompress(
        #"89218ac9d46dbef17651a764dd5e0ee7414b040221e3d0f188642129acfea1a17862de38851b2483095449c4732d150a",
      ),
    }
  let commit =
    #"1669f6cef337b4373a0f3e6307c6cdfb44517a36e125d7866ee9e838f4f5455cca63ce114d25b62ae4e597dc78c4db45170d8abb0611028477e44388db31dccbee44f308b8f5cd934727ede4202b807fe1e7ba3c0d7c0680c9213dd84a29576d"
  do_ecdsa_verify(pk, sign, commit)
}

test run_sha256() {
  let msg =
    #"1640ec7d49e120b3fc0af85d4780d7ca7a2842db2384b1243da395307c5095bf4c247bf86158fd415cf5f9608b138e4c0e866a62d122b21a863240dec6dc1f8f7d9ec1f463e334f86a8cf71a561d30be335367bd2dcc79d4e8b812d03dddc698"
  let digest =
    #"bec55a5a88c41b777d091822faf509a0c596034b48316458674278d4134f998c"
  expect digest == sha2_256(msg)
  expect
    from_bytearray_big_endian(digest) % scalar.field_prime == 33852258525425321746310890315453146691709421431852632660276518292211947772299
}

pub fn bytearray_big_endian_to_int(bytearray: ByteArray) -> Int {
  let number = from_bytearray_big_endian(bytearray)
  number % scalar.field_prime
}

pub fn g1_to_binary256(g1: ByteArray) -> ByteArray {
  sha2_256(g1)
}

pub fn g2_to_binary256(g2_1: ByteArray, g2_2: ByteArray) -> ByteArray {
  sha2_256(concat(g2_1, g2_2))
}

pub fn list_g1_to_binary256(g1_list: List<ByteArray>) -> ByteArray {
  let first = head(g1_list)
  if is_none(first) {
    #""
  } else {
    expect Some(first_) = first
    let first_bytes = g1_to_binary256(first_)
    let tail = tail(g1_list)
    expect Some(tail_) = tail
    let tail_bytes = list_g1_to_binary256(tail_)
    concat(first_bytes, tail_bytes)
  }
}

test test_gen_challage() {
  let g1_list =
    [
      #"b1fbe330769a11acc36fc723335b0220323273e006f2b6fdb9db39ea82e7c183",
      #"547f53c1288c939a559451dcb4d99da1bf3ef35224a5ee6c7a3dac1c2cef9c4a",
      #"d2a6c4b52043c21686fdcf43d5622de40c167219e8526b580a49204c580341d7",
      #"bbd3bae6db2033733cc3484078b925ad0ba516e520bcabd8799f5a56882534bb",
      #"c667841fee4b35de2f3275637406e52398a3f528dc5b4a17bc396552ee421fc8",
      #"b95e27b84bcc547b495e0b233aecb9b7b3e4cd5be806ed8315bc50c3a8dd9a24",
      #"0c7501c9b05fdbcc05964420eea6dbcc715e9572f104f0c7d3c6a54082f51fd6",
      #"45cb7ad5b7af47f5f1386111d850b3bf70d0152af176d191794f592df2420ffd",
      #"f69d7e0b2146a02600e46e5f43d980840c5999aa2b5dfc69b9516ca001ee3df3",
      #"653615fdea02594062eb0ec9dcc2fb0cf41f7691ae732f273eeeb65d8cb67193",
      #"b1886e6f2cd500a53aab252c28610f8f0717544144635345b7e76b3f799d058b",
      #"bfeca6ac00ad31f8112e513c66274946bad70fde237718288eca96d55de93510",
      #"75ec37025834933b891bb9e643938c631e67d127b6125b472e211ae65d4b0ab3",
      #"2c9d0dc2d3bedf791d7e5c811db7c54dc9695f00ec20b81d1d51eff4c969b6dd",
      #"0b87473b8fa3252bc28383060c3ee965c4a0ceadb94c0aa731c20a7a48bd7e0a",
      #"f38795079d77abd6d065cfb937e36064dadc485eab46c20dec26a5ea184fab37",
      #"4990b6e0f020d5911b4ec935b65f4e286b17a24ffa39ce400526717c9a92506e",
      #"53b7af58974e770c425eafb96b2da0ec0d3918ad9e5d90afd9c9ae9176de6999",
    ]
  let all = concat_list(g1_list)
  let c = sha2_256(all)
  expect
    c == #"c8f1bc5dd31ee1f58da9c4541c1ed9fd258476d74ba2e145a8b25596685f5bc4"
}

fn concat_list(list: List<ByteArray>) -> ByteArray {
  let first = head(list)
  if is_none(first) {
    #""
  } else {
    expect Some(first_) = first
    let first_bytes = first_
    let tail = tail(list)
    expect Some(tail_) = tail
    let tail_bytes = concat_list(tail_)
    concat(first_bytes, tail_bytes)
  }
}
