use aiken/builtin.{bls12_381_final_verify}
use aiken/collection/list.{head}
use aiken/crypto.{sha2_256}
use aiken/crypto/bls12_381/g1 as g1
use aiken/crypto/bls12_381/g2 as g2
use aiken/crypto/bls12_381/scalar
use aiken/primitive/bytearray.{concat}
use aiken/primitive/int.{from_bytearray_big_endian}
use bls.{
  g1_to_binary256, g2_to_binary256, group_pairing, int_to_binary256,
  list_bytearray_to_g1, list_compressed_to_g2, list_g1_to_binary256,
  list_g2_to_binary256, list_to_binary256,
}

pub type Proof {
  c: Int,
  rm: List<Int>,
  rt: Int,
}

pub type Theta {
  kappa: G2Element,
  nu: G1Element,
  sigma: List<G1Element>,
  proof: Proof,
}

pub fn verify_cred(
  theta: Theta,
  aggr: ByteArray,
  alpha: ByteArray,
  aw: ByteArray,
  beta: List<ByteArray>,
  disclose_attr: List<Int>,
  timestamp: Int,
  hs: List<ByteArray>,
) {
  // Bw = add(multiply(nu, c), multiply(h, rt))
  expect Some(c_sca) = scalar.new(theta.proof.c)
  expect Some(rt_sca) = scalar.new(theta.proof.rt)
  expect Some(h) = head(theta.sigma)
  let bw = g1.add(g1.scale(theta.nu, c_sca), g1.scale(h, rt_sca))
  expect
    verify_pi_v(
      g2.decompress(alpha),
      theta,
      g2.decompress(aw),
      bw,
      list_compressed_to_g2(beta),
      disclose_attr,
      timestamp,
      list_bytearray_to_g1(hs),
    )
  expect Some(sigma_head) = list.head(theta.sigma)
  expect Some(sigma_last) = list.last(theta.sigma)
  let coord1 = sigma_head
  let coord2 = g1.add(sigma_last, theta.nu)
  let coord3 = g2.add(theta.kappa, g2.decompress(aggr))
  let coord4 = g2.generator
  let pair1 = group_pairing(coord1, coord3)
  let pair2 = group_pairing(coord2, coord4)
  bls12_381_final_verify(pair1, pair2)
}

test verify_cred_test() {
  True
  // let theta =
  //   Theta {
  //     kappa: g2.decompress(
  //       #"8a420f7c74ba70c2850f4d75caa81e8fbc0927816de4b2dfe840a233975f5fa1c064c9f1ceb7e7e843eb1401e6f16cb206fd33d015e0787fb7f81738451759466e62d03389f0bdb81ef46e63772e8bd969c68f1995ac3054f6d84a258682424c",
  //     ),
  //     nu: g1.decompress(
  //       #"a78353cb5a8617bbefca2699945c757b9ed778f85a20416ca223eb1dd0a69c2640a099efa50822afaaa882870f6d9e50",
  //     ),
  //     sigma: [
  //       g1.decompress(
  //         #"b68a6c29f56f6b74de211d4b300521e26e7f88156fac57fae42698fb6ad4b02311209f4e0617bab887956268d8eff33d",
  //       ),
  //       g1.decompress(
  //         #"a69855e3880d704863e0aa7e4013ab54934a10de9ca5b508072ecc793e4999ffc31af6eeae90373bb2dd71f6693cc433",
  //       ),
  //     ],
  //     proof: Proof {
  //       c: 114431169388587258780645030011577685699312481543177991797007112837362091849757,
  //       rm: [
  //         21718534856770756634793260627382033630981292992841827025429155841891380318983,
  //         44892737665039948170684589675722777067852000479314165487097319164043954222564,
  //         21718534856770756634793260627382033630981292992841827025429155841891380318983,
  //         41396620339627670471775508533158557559093467337098503342186355902616978827244,
  //       ],
  //       rt: 1749025775,
  //     },
  //   }
  // let aggr =
  //   #"b9cbb99e1250991e4d365a48540e254c7dca4af62d77b804a4b05d4ed87d85f312f8e7759f6720e94cb6fac65ca21f891909ebbb242bb735eb684154a1e9f580ea0bab14043d660f79b953621a8ba7d3e242db6bbbb9f5bbed5b8cfbfefef210"
  // verify_cred(theta, aggr)
}

pub fn verify_pi_v(
  alpha: G2Element,
  theta: Theta,
  aw: G2Element,
  bw: G1Element,
  beta: List<G2Element>,
  disclose_attr: List<Int>,
  timestamp: Int,
  hs: List<G1Element>,
) -> Bool {
  let challenge =
    to_challenge_verify(
      alpha,
      aw,
      bw,
      theta.kappa,
      hs,
      beta,
      disclose_attr,
      timestamp,
    )
  theta.proof.c == from_bytearray_big_endian(challenge)
}

test to_challenge_verify_test() {
  let c =
    114431169388587258780645030011577685699312481543177991797007112837362091849757
  let kappa =
    g2.decompress(
      #"aa0ad8e2c5bbd2fa77d58e5d7cd3561fe648439f9245d8d3d89a6f7609a0a95c6320791f286c8e721b1512fc3eb5d78e17c769c47a398554289fb85d811c8bb576308d6e402940da711908d757802da57040fe787423d9c1f586b55275154a69",
    )
  let timestamp = 1749025775
  let disclose_attr =
    [
      21718534856770756634793260627382033630981292992841827025429155841891380318983,
      44892737665039948170684589675722777067852000479314165487097319164043954222564,
      21718534856770756634793260627382033630981292992841827025429155841891380318983,
      41396620339627670471775508533158557559093467337098503342186355902616978827244,
    ]
  let beta =
    [
      g2.decompress(
        #"8ddcf056acee4515ef9fa1dbc4783e7dd18c19cc6267eb39f708c70f6424fc86db575bd1b3999645079ea8bf3333e045155184ca03164542e1c7dd6362207062aed03c6e031994285018820c69710420d67922d0fd11972b1f1537b021c2d793",
      ),
      g2.decompress(
        #"915a30e54c1d68b46c4a9f2df0ff10c4e77ddca7929cbd5960956f05e8ad9f34b360ed81fc538492df75b56d8bba13a80c35af5547ab911c0ca74b94a20b5c24ed846fa6c093fd9bc820948a2f226ada844a85099f4ef6b0c2d9c3077dbef651",
      ),
      g2.decompress(
        #"88357fd2dce6145524be86941c90d7316f3969e79f87c190769933334856cf45f6bdaaa0b203235bcbb4bb07acb3c616139c23c797a4212b3cf7f228997ff0d39cd21ca8f7312d19baac00fae65191866aa0ee6a2b1c7f54d315514867a33986",
      ),
      g2.decompress(
        #"ae14764cc482731067d51777cb594220d1df682cb9db30ee53ce03755a08c2d0ee04d2f869b5982aa9e9cbebb1fccc7d180e4643849fc90688447b89ed6aea841497b46266d50e25cf474597bfa60eeafd3b65a775101144f6b84ece2f1cd2f5",
      ),
      g2.decompress(
        #"b727aef20acafc3248e4ae0b4f28cd5acc63ad43a2c0118037dcb7d8e13294a325a3f49d2706b102dbc6d84ca208a914096ca003e07b354517c7bfd1dd52114de5ba3e3f458b731f489b2ef3520ee3a8afffa7f1f912809b21034b476106075e",
      ),
      g2.decompress(
        #"95a6f98510fcb1f05cad9678b6820c88ee078246e5c275e98682b25a72e7f8fa4477234e62e98064795ebd51b8bf6f0406b112b0c371c583f6170909b434998378bbe736e902aefcecb787f19f5df463e66c2ebdf91a9faef68f725a4d59718d",
      ),
      g2.decompress(
        #"953790bab8515fb5db7bdfc262be72227e17da4becfe679a3dee7c1966a96046dd7b994f1340904118d84dd53618c601090041aeac7d9584d753c167f53aa9cc8f4fa545ab0307aee1185af98c6739b67ecbdc40c7d1abf945b682a175fd3e55",
      ),
    ]
  let hs =
    [
      g1.decompress(
        #"a090cfe9261fdcfbe1b0b3f74256e57f6a5bdd98c13b0e09f9484838b02239a0ab8b883b7910585c13918f995eb8df89",
      ),
      g1.decompress(
        #"865341b6a4affbe3b795d2d3c71781ad7267849fe2b24e728e13524d60d08e5a1681344b20268ea337d2fa2c1c3bbd7c",
      ),
      g1.decompress(
        #"ae1dc44ad2d3084be3574e5feb59476b1c530322c1eab7d9a869372899cdfa75279ff5119ca6d2980e9e022a98a0ba6b",
      ),
      g1.decompress(
        #"b358409e76fa35a23ec6f3e88bd963eb9da3ad83e59e3c005a3b4e050061fda1fe56227dcec8610061073795fb259b50",
      ),
      g1.decompress(
        #"8bb97519cdb28bb8ceab19bb289c02856a542da4ce52fd3c2cbe8914986f7162a2632e94a6420e47c3d7503f2024fb3d",
      ),
      g1.decompress(
        #"8d06e182789336765f00589a3dd16690ad368d656e95a4b7709bb7ba686d17ae7df5f23e91270bccf334632b3c86df99",
      ),
      g1.decompress(
        #"994278e9661d267e2eaec3fee0a9302fc58347be0466778ea4ba55c9ca426a9856ef7479fc381e7408a9e01da5cc24de",
      ),
    ]
  let aw =
    g2.decompress(
      #"b980e01a63cd555b4a2e74c8bc2f77d18eece709cccaf247d2961e9207f73b3cbfb9f845a3eaf9b7b98438195d229e990e6c66ae496d58858e516ad233cbd5c975de029a0ac3d93a985274df41b114e62d0613797c7dd707e9a1f49b27377a20",
    )
  let bw =
    g1.decompress(
      #"a6152e01e4c6a26a2650d4d449ff62fe0d51468459e345c17d8fb5e0ecca7697758ad4d94fc894ccba4656e2ba2e21c9",
    )
  let alpha =
    g2.decompress(
      #"8a9aae69dd5f3e8b0ab1f5e371d60562cdf5df30371ae0ad57211c2e001654bf2c020d9270425a70395f0182dc35f646125b276cf9b37e367710e9aed953fd40316ec9e05478c01e12392379f04bbcbc0850cd1971642ab197eb7419f07d8923",
    )

  c == from_bytearray_big_endian(
    to_challenge_verify(
      alpha,
      aw,
      bw,
      kappa,
      hs,
      beta,
      disclose_attr,
      timestamp,
    ),
  )
}

pub fn to_challenge_verify(
  alpha: G2Element,
  aw: G2Element,
  bw: G1Element,
  kappa: G2Element,
  hs: List<G1Element>,
  beta: List<G2Element>,
  disclose_attr: List<Int>,
  timestamp: Int,
) -> ByteArray {
  let g1_bytes = g1_to_binary256(g1.generator)
  let g2_bytes = g2_to_binary256(g2.generator)
  let alpha_bytes = g2_to_binary256(alpha)
  let aw_bytes = g2_to_binary256(aw)
  let bw_bytes = g1_to_binary256(bw)
  let kappa_bytes = g2_to_binary256(kappa)
  let hs_bytes = list_g1_to_binary256(hs)
  let beta_bytes = list_g2_to_binary256(beta)
  let disclose_attr_bytes = list_to_binary256(disclose_attr)
  let timestamp_bytes = int_to_binary256(timestamp)
  let first_c = concat(g1_bytes, g2_bytes)
  let second_c = concat(first_c, alpha_bytes)
  let third_c = concat(second_c, aw_bytes)
  let fourth_c = concat(third_c, bw_bytes)
  let fifth_c = concat(fourth_c, kappa_bytes)
  let sixth_c = concat(fifth_c, hs_bytes)
  let seventh_c = concat(sixth_c, beta_bytes)
  let eighth_c = concat(seventh_c, disclose_attr_bytes)
  let ninth_c = concat(eighth_c, timestamp_bytes)
  sha2_256(ninth_c)
}
