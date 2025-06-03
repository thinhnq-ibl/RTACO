use aiken/builtin.{
  bls12_381_final_verify, bls12_381_g1_neg, bls12_381_g1_scalar_mul,
  bls12_381_g2_hash_to_group, bls12_381_g2_scalar_mul, bls12_381_miller_loop,
  bls12_381_mul_miller_loop_result, bytearray_to_integer,
}
use aiken/collection/list
use aiken/crypto.{sha2_256}
use aiken/crypto/bls12_381/g1 as g1
use aiken/crypto/bls12_381/g2 as g2
use aiken/crypto/bls12_381/scalar
use aiken/primitive/bytearray.{concat}
use aiken/primitive/int.{from_bytearray_big_endian}
use bls.{
  Sign, do_ecdsa_verify, g1_to_binary256, g2_to_binary256, group_pairing,
  list_bytearray_to_g1, list_compressed_to_g1, list_g1_to_binary256,
}

// require(verify_pi_v(name, [theta.sigma[0], theta.nu], [Aw, theta.kappa], theta.proof, beta, disclose_attr, disclose_attr_enc, disclose_index, _timestamp));
//     uint256[] memory public_m_enc = params.get_public_m_encoding(name);
//     if(public_m.length != 0) {
//       require(check_aggr(public_m, public_m_enc, aggr, beta, theta.proof.rm.length+disclose_attr.length));
//     }
//     G.G1Point[] memory coord1 = new G.G1Point[](2);
//     G.G2Point[] memory coord2 = new G.G2Point[](2);
//     coord1[0] = G.g1neg(theta.sigma[0]);
//     coord1[1] = G.g1add(theta.sigma[1], theta.nu);
//     coord2[0] = G.g2add(theta.kappa, aggr);
//     coord2[1] = G.P2();
//     require(!G.isinf(theta.sigma[0]) && G.pairing(coord1, coord2));
pub type Proof {
  c: Int,
  rm: List<Int>,
  rt: Int,
}

pub type Theta {
  kappa: G2Element,
  nu: G1Element,
  sigma: List<G1Element>,
}

//   proof: Proof,

pub fn verify_cred(theta: Theta, aggr: G2Element) {
  expect Some(sigma_head) = list.head(theta.sigma)
  expect Some(sigma_last) = list.last(theta.sigma)
  let coord1 = sigma_head
  let coord2 = g1.add(sigma_last, theta.nu)
  let coord3 = g2.add(theta.kappa, aggr)
  let coord4 = g2.generator
  let pair1 = group_pairing(coord1, coord3)
  let pair2 = group_pairing(coord2, coord4)
  bls12_381_final_verify(pair1, pair2)
}

test verify_cred_test() {
  let theta =
    Theta {
      kappa: g2.decompress(
        #"8a420f7c74ba70c2850f4d75caa81e8fbc0927816de4b2dfe840a233975f5fa1c064c9f1ceb7e7e843eb1401e6f16cb206fd33d015e0787fb7f81738451759466e62d03389f0bdb81ef46e63772e8bd969c68f1995ac3054f6d84a258682424c",
      ),
      nu: g1.decompress(
        #"a78353cb5a8617bbefca2699945c757b9ed778f85a20416ca223eb1dd0a69c2640a099efa50822afaaa882870f6d9e50",
      ),
      sigma: [
        g1.decompress(
          #"b68a6c29f56f6b74de211d4b300521e26e7f88156fac57fae42698fb6ad4b02311209f4e0617bab887956268d8eff33d",
        ),
        g1.decompress(
          #"a69855e3880d704863e0aa7e4013ab54934a10de9ca5b508072ecc793e4999ffc31af6eeae90373bb2dd71f6693cc433",
        ),
      ],
    }
  let aggr =
    g2.decompress(
      #"b9cbb99e1250991e4d365a48540e254c7dca4af62d77b804a4b05d4ed87d85f312f8e7759f6720e94cb6fac65ca21f891909ebbb242bb735eb684154a1e9f580ea0bab14043d660f79b953621a8ba7d3e242db6bbbb9f5bbed5b8cfbfefef210",
    )
  verify_cred(theta, aggr)
}
