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

// start
// elements b1fbe330769a11acc36fc723335b0220323273e006f2b6fdb9db39ea82e7c183
// elements 547f53c1288c939a559451dcb4d99da1bf3ef35224a5ee6c7a3dac1c2cef9c4a
// elements d2a6c4b52043c21686fdcf43d5622de40c167219e8526b580a49204c580341d7
// elements bbd3bae6db2033733cc3484078b925ad0ba516e520bcabd8799f5a56882534bb
// elements c667841fee4b35de2f3275637406e52398a3f528dc5b4a17bc396552ee421fc8
// elements b95e27b84bcc547b495e0b233aecb9b7b3e4cd5be806ed8315bc50c3a8dd9a24
// elements 0c7501c9b05fdbcc05964420eea6dbcc715e9572f104f0c7d3c6a54082f51fd6
// elements 45cb7ad5b7af47f5f1386111d850b3bf70d0152af176d191794f592df2420ffd
// elements f69d7e0b2146a02600e46e5f43d980840c5999aa2b5dfc69b9516ca001ee3df3
// elements 653615fdea02594062eb0ec9dcc2fb0cf41f7691ae732f273eeeb65d8cb67193
// elements b1886e6f2cd500a53aab252c28610f8f0717544144635345b7e76b3f799d058b
// elements bfeca6ac00ad31f8112e513c66274946bad70fde237718288eca96d55de93510
// elements 75ec37025834933b891bb9e643938c631e67d127b6125b472e211ae65d4b0ab3
// elements 2c9d0dc2d3bedf791d7e5c811db7c54dc9695f00ec20b81d1d51eff4c969b6dd
// elements 0b87473b8fa3252bc28383060c3ee965c4a0ceadb94c0aa731c20a7a48bd7e0a
// elements f38795079d77abd6d065cfb937e36064dadc485eab46c20dec26a5ea184fab37
// elements 4990b6e0f020d5911b4ec935b65f4e286b17a24ffa39ce400526717c9a92506e
// elements 53b7af58974e770c425eafb96b2da0ec0d3918ad9e5d90afd9c9ae9176de6999
// Chash c8f1bc5dd31ee1f58da9c4541c1ed9fd258476d74ba2e145a8b25596685f5bc4
// Aw ['166241f947b01106dc59ea1fe8e3df1309fcb1fcfa094ae246021a2b56e4e8776dc34ac7ec92b2d12ea1a5267e4acde2006d8549d511ace2d2bf6af0ea9fc203cb9e155049868b4b7dbfe82d0e5cc56fcbff573d662aba87ec8bad96578ebd75', '0541d95c30d9f26feb7d045d4eb00e9abce4b64cb9a3a4f2aa17d72fa7191ff30acb5ec52b0fc207212368b5264da9010fd34454ed4e80cd029563db444f5f49380d2be3d75f6c0ed722313ce5b1e8f385d07e95b5a766750ecf9036afbea4d6', '116e20c73c34e537550c82965d8827ce6e56a0256d5951069fd4a21b177114ab0f12b9b5031924e2cfafdb645c1361c019dac88947992a883289ebb02e9599308d5c44d640476543992d4ea1c6d61572afb592f0df3e8790fbf9ebbe3b13c7a1', '0f9fcb3f72dacc753252ac8f394522180d8789b47571d03169f2c652e4a3c1680cbb58f265b6280264b6a3cc27991c5714d34345913ef131f49c0d3114d4cf84540cf88ec29b67e964188d0e6686aaad146b38af8d0d4f4d74f1f30843f4748d']
// Bw 1705263a9cc42459ec795eab378681c21529f1caebc75b4942f7bc4f04b745c74faaa9147e54d24a6919f54f724239c1164af1fd1ac4a2ff8529de30a907fa51175367b4da543030deda7723f47305705561bad5758291105d2543146ce1c2c3
// Cw ['16519e13edea4fe7472ccb1eb8c084e0ad6549341c90e5e9d3e731c5cebbc19997a026cdaec7005ce4bcb102f3000967026f2b2262e3a5b113a7042af2966e29bf180d31ec971b81c737996fa2114a0a0c7d2f784d829936818459c63432c7a6', '0a4b1e237cb18d6bc03ed00efd7e7ddc18229fe35ebc3191594969e884874e9fe31d87065b033f23d0bb7f882aee0fca082a0eff7c55972156113c5917adbf04beb9784c535e3f99cf1bd6a72ea4d9c93e4cb48ee3f0f99bd0f3ab69b899f2e4']
// g1 17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1
// g2 ['024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb813e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e', '0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b828010606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be']
// cm 0a52d3212c09ef8aa23574c8ff1ea9c3d8b531bf67b75747ea80398a628185063e15065a80a4e17b9b5ec24088d46e550ac9f02f6a9831ccff01860cd0bbaad22ddbcf283832cbddd2b4bf830e0655334e9ec7c50688718ef6080274114becf4
// h 0478274c35d83186d1ccd6a83369e4bd3e19daecda41beba0ffa3f32dc187dc38dda71b7b4b2080b4d2c408678e769fc0ac142467746328ebad4414aca141f580f4c36e017c73e109e34261ce22ea84b9ad0ec675bc0852fea8938fe1611fb91
// hs ['0090cfe9261fdcfbe1b0b3f74256e57f6a5bdd98c13b0e09f9484838b02239a0ab8b883b7910585c13918f995eb8df891655908d3acb820cfcd2b69aa43c6df453bfb957fb8b6dd4dc477c5b7d43cc93d9746c0c3d1a8c8f32876d08aed48ee8', '065341b6a4affbe3b795d2d3c71781ad7267849fe2b24e728e13524d60d08e5a1681344b20268ea337d2fa2c1c3bbd7c025278d0bb80f8ccde8dfdbabf5f47a1249923e9e1e6e2b21df08781ed6cdc10947dfd51301e0c67ce724ca7d70841ef', '0e1dc44ad2d3084be3574e5feb59476b1c530322c1eab7d9a869372899cdfa75279ff5119ca6d2980e9e022a98a0ba6b16c3b8d1513387714a0febf64bdac7c2cabd3e07828a8793118f4a5c52f4492ebec48ea4e992c3022706bbcaf7eaf2e2', '1358409e76fa35a23ec6f3e88bd963eb9da3ad83e59e3c005a3b4e050061fda1fe56227dcec8610061073795fb259b5014d7a833b904c59be96015957f7cf97efd49dc61f54654a29223853d635ba465c91faf3e03f7abbabcd0fb7d4457c248', '0bb97519cdb28bb8ceab19bb289c02856a542da4ce52fd3c2cbe8914986f7162a2632e94a6420e47c3d7503f2024fb3d04814cc4d389d20599620a1a9f1adb3497b06434d39fcdd0e886b50fd750a87375e466393c587e6f52a034a576cd95be', '0d06e182789336765f00589a3dd16690ad368d656e95a4b7709bb7ba686d17ae7df5f23e91270bccf334632b3c86df9904384131406f288bc275cfe2ea683130b2867e3f960e1065f3a777b0a9f16ac07805790a4c797d080e325fa13abf8d6d', '194278e9661d267e2eaec3fee0a9302fc58347be0466778ea4ba55c9ca426a9856ef7479fc381e7408a9e01da5cc24de02b410d38dc25307f1741568f84700e4ddf6af326631024d34327279e909383c0c0b3061ee6068225c21186c4a164e4e']
// c 90889679917086702897764874634553305957805027920137946837610029982752513678276

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
