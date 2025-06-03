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
  proof: Proof,
}

pub fn verify_cred(theta: Theta, aggr: G2Element) {
  expect Some(sigma_head) = list.head(theta.sigma)
  expect Some(sigma_last) = list.last(theta.sigma)
  let coord1 = builtin.bls12_381_g1_neg(sigma_head)
  let coord2 = g1.add(sigma_last, theta.nu)
  let coord3 = g2.add(theta.kappa, aggr)
  let coord4 = g2.generator
  let pair1 = group_pairing(coord1, coord3)
  let pair2 = group_pairing(coord2, coord4)
  bls12_381_final_verify(pair1, pair2)
}
