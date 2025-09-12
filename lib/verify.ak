use aiken/builtin.{bls12_381_final_verify}
use aiken/collection/list.{head}
use aiken/crypto.{sha2_256}
use aiken/crypto/bls12_381/g1 as g1
use aiken/crypto/bls12_381/g2 as g2
use aiken/crypto/bls12_381/scalar
use aiken/primitive/bytearray.{concat}
use aiken/primitive/int.{from_bytearray_big_endian}
use bls.{
  G1PointByteArray, G2PointByteArray, g1_to_binary256, g2_to_binary256,
  group_pairing, int_to_binary256, list_bytearray_to_g1, list_compressed_to_g2,
  list_g1_to_binary256, list_g2_to_binary256, list_to_binary256, to_g2,
}

pub type Proof {
  c: Int,
  rm: List<Int>,
  rt: Int,
}

pub type Theta {
  kappa: G2PointByteArray,
  nu: G1Element,
  sigma: List<G1Element>,
  proof: Proof,
}

pub fn verify_cred(
  theta: Theta,
  aggr: List<ByteArray>,
  alpha: G2PointByteArray,
  aw: G2PointByteArray,
  beta: List<G2PointByteArray>,
  disclose_attr: List<Int>,
  timestamp: Int,
  hs: List<G1PointByteArray>,
) {
  expect Some(c_sca) = scalar.new(theta.proof.c)
  expect Some(rt_sca) = scalar.new(theta.proof.rt)
  expect Some(h) = head(theta.sigma)
  let bw = g1.add(g1.scale(theta.nu, c_sca), g1.scale(h, rt_sca))
  expect
    verify_pi_v(
      to_g2(alpha),
      theta,
      to_g2(aw),
      bw,
      list_compressed_to_g2(beta),
      disclose_attr,
      timestamp,
      list_bytearray_to_g1(hs),
    )
  expect Some(sigma_last) = list.last(theta.sigma)
  let coord1 = h
  let coord2 = g1.add(sigma_last, theta.nu)
  let aggr_point =
    if list.length(aggr) != 0 {
      to_g2(aggr)
    } else {
      g2.zero
    }
  let coord3 = g2.add(to_g2(theta.kappa), aggr_point)
  let coord4 = g2.generator
  let pair1 = group_pairing(coord1, coord3)
  let pair2 = group_pairing(coord2, coord4)
  bls12_381_final_verify(pair1, pair2)
}

test verify_cred_test() {
  let theta =
    Theta {
      kappa: [
        #"878a8ad400fad9651450254eb59e00d32430106965d2d3c17a7888152249440ff00cfb731c9e70ab05b2b1794fd4f296",
        #"0b07b8c368b4f00072bc7e6b9c74723e6fd6ffbe59bb7889da38d51a52e5f6086f3d60033ea8567114f9409f3d230a9b",
      ],
      nu: g1.decompress(
        #"a6e229247ef0dea50213e7245216c948d3e8471a32d2a65a6d74e6edf4911bc04bd7165f227cd4358ad0da8f745ab843",
      ),
      sigma: [
        g1.decompress(
          #"a818baa56c6c069f45b09833057480298637af3eb20f2aed46314dff3ecce01d47d35cf27cf57e511b248daaa24245ea",
        ),
        g1.decompress(
          #"9117e4f0f81c8483d8cd6967ce547e1af18bfe85e0cf59aba25b3c6668b2e3a740e49131a5c7e8bfef4466c3a58e6f28",
        ),
      ],
      proof: Proof {
        c: 43953825675714075024391357470089393824546011683396945525107498247681984930981,
        rm: [
          33201398774658044924842383368859864201050291569118115993700463891168183954704,
          1886665901031710547374862922187803698730842134686358055213993339908120500534,
        ],
        rt: 34386718347699404645595550243171262552307584501849354162591548582147168255223,
      },
    }
  let aggr = []
  let alpha =
    [
      #"a277357a6c44f5080f27ce2964d0b0e7c3e590d0e48dc0e032436ae15cbd435082e2266baed48398432ab43446337c21",
      #"0f654ac4e8d02c6aefa7ebe4dac7691c4d2fc84cf9b349c9cfac1e34c1be67e1728662697bdd59ba11df76880a588194",
    ]
  let wa =
    [
      #"861a318ec595e5b1b366ba6066558bf89cd2a93f5885b678486ffa58ccf9beea1f129e7bac57b1ea13cb9a2bc4d58eb1",
      #"0a92d4217f1e2df21207347602d9e0f9edbaf3ee2f7b148bee82e7e3448b82a96810196a751570cabf559e73ed26f376",
    ]
  let beta =
    [
      [
        #"87aa5e894fa26828d65a083287a8a271f1217ab4b681f9653d0f85c073532be85e57b8ebe394ae4bfe1dcae7b8745ac2",
        #"15dfc642cc4c9cb1703cd25806ef7aa8dfdcd2d36a7c0b8e4165dfa283abc2d386b794f34a32014e9820ef41681ef7f2",
      ],
      [
        #"a69c24fdb1f77e1b0b1656d642f2205f2aff2b68fe2a8af6a8f1c77b5f743f31c639d11521d35f344fb52cd847fafbb2",
        #"106c7075a1d888351ca6b62a8adf67d76b56479076d8dcb1642019ebf8a69680bf4c2f0f909ac84ecff05dec923bd8ba",
      ],
    ]
  let disclose_attr = []
  let timestamp = 1753846862
  let hs =
    [
      #"a090cfe9261fdcfbe1b0b3f74256e57f6a5bdd98c13b0e09f9484838b02239a0ab8b883b7910585c13918f995eb8df89",
      #"865341b6a4affbe3b795d2d3c71781ad7267849fe2b24e728e13524d60d08e5a1681344b20268ea337d2fa2c1c3bbd7c",
    ]
  verify_cred(theta, aggr, alpha, wa, beta, disclose_attr, timestamp, hs)
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
      to_g2(theta.kappa),
      hs,
      beta,
      disclose_attr,
      timestamp,
    )
  theta.proof.c == from_bytearray_big_endian(challenge) % scalar.field_prime
}

test to_challenge_verify_test() {
  let c =
    43953825675714075024391357470089393824546011683396945525107498247681984930981
  let kappa =
    [
      #"878a8ad400fad9651450254eb59e00d32430106965d2d3c17a7888152249440ff00cfb731c9e70ab05b2b1794fd4f296",
      #"0b07b8c368b4f00072bc7e6b9c74723e6fd6ffbe59bb7889da38d51a52e5f6086f3d60033ea8567114f9409f3d230a9b",
    ]
  let timestamp = 1753846862
  let disclose_attr = []
  let beta =
    [
      g2.decompress(
        #"87aa5e894fa26828d65a083287a8a271f1217ab4b681f9653d0f85c073532be85e57b8ebe394ae4bfe1dcae7b8745ac215dfc642cc4c9cb1703cd25806ef7aa8dfdcd2d36a7c0b8e4165dfa283abc2d386b794f34a32014e9820ef41681ef7f2",
      ),
      g2.decompress(
        #"a69c24fdb1f77e1b0b1656d642f2205f2aff2b68fe2a8af6a8f1c77b5f743f31c639d11521d35f344fb52cd847fafbb2106c7075a1d888351ca6b62a8adf67d76b56479076d8dcb1642019ebf8a69680bf4c2f0f909ac84ecff05dec923bd8ba",
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
    ]
  let aw =
    g2.decompress(
      #"861a318ec595e5b1b366ba6066558bf89cd2a93f5885b678486ffa58ccf9beea1f129e7bac57b1ea13cb9a2bc4d58eb10a92d4217f1e2df21207347602d9e0f9edbaf3ee2f7b148bee82e7e3448b82a96810196a751570cabf559e73ed26f376",
    )
  let bw =
    g1.decompress(
      #"a7532196fcb8f4f58206e83bb1cc29ecf9e8292c19cb462ba3cb27357067133e04f901963a9f335ae47c98cfaa51aac0",
    )
  let alpha =
    g2.decompress(
      #"a277357a6c44f5080f27ce2964d0b0e7c3e590d0e48dc0e032436ae15cbd435082e2266baed48398432ab43446337c210f654ac4e8d02c6aefa7ebe4dac7691c4d2fc84cf9b349c9cfac1e34c1be67e1728662697bdd59ba11df76880a588194",
    )

  c == from_bytearray_big_endian(
    to_challenge_verify(
      alpha,
      aw,
      bw,
      to_g2(kappa),
      hs,
      beta,
      disclose_attr,
      timestamp,
    ),
  ) % scalar.field_prime
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
