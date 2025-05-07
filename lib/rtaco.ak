use aiken/builtin.{
  bls12_381_final_verify, bls12_381_g1_add, bls12_381_g1_compress,
  bls12_381_g1_scalar_mul, bls12_381_g1_uncompress, bls12_381_g2_add,
  bls12_381_g2_compress, bls12_381_g2_hash_to_group, bls12_381_g2_scalar_mul,
  bls12_381_g2_uncompress, bls12_381_miller_loop,
  bls12_381_mul_miller_loop_result, bytearray_to_integer,
}
use aiken/collection/list.{foldl, head, length, range, tail}
use aiken/crypto/bls12_381/g1 as g1
use aiken/crypto/bls12_381/g2 as g2
use aiken/crypto/bls12_381/scalar as scalar
use aiken/option.{is_none}
use bls.{Sign, do_ecdsa_verify}

//  function check_Vcerts(string memory name, Vcert[] memory vcerts, IssueProof memory iproof) private view returns(bool) {
//         // require(isRequested(name, vcerts[0]), "Verifiable certificate already used.");
//         bool evaluated;
//         string[] memory combination = iproof.combination;
//         require (vcerts.length == combination.length, "Bad combination.");
//         uint256 id = params.getMapCredentials(name);
//         require(id != 0, "No such AC.");
//         require(params.checkCombination(id, combination), "Bad combination.");
//         for (uint256 i = 0; i < vcerts.length; i++) {//each Vcert is done ECC verification
//             evaluated = G.do_ecdsa_verify(vcerts[i].commit, params.get_ttpKeys(combination[i]), vcerts[i].signature);
//             if(!evaluated) {
//                 return false;
//             }
//         }
//         require(check_sk(iproof), "master secret key verification failed");
//         return true;
//     }

pub type Vcert {
  commit: ByteArray,
  signature: Sign,
}

pub type IssueProof {
  c: Int,
  rr: Int,
  ros: List<Int>,
  total_rm: List<List<Int>>,
  pubkeys: List<G1Element>,
}

const iproof =
  IssueProof {
    c: 111028293681481776174710511636606709440469689910069175151354337820721184534253,
    rr: 5050437177520903155847248449104124878646040665278897517070821451493842774601,
    ros: [
      49744196328279248815796712426546829894584294309244497450305853101602225222529,
      29782732702853354121904336237005215317539472786765989838419548536149186648559,
      3986513954939188089344606671398402557201798092878666912131712831328580791987,
      42926437779922011362364629289975177979465250943458230974890693324059432914956,
    ],
    total_rm: [
      [
        28570405751608929143275229779994869610628602755456909429086846981825913832910,
        13507742991005023007096234598351915058180043055507780815574349619528610865134,
        26806696748710448407371037207606330670021875901994732626874438952060518010483,
        14337009862152980476725691075380459026334552202534707298997180022700568755898,
      ],
      [
        28570405751608929143275229779994869610628602755456909429086846981825913832910,
        45279309888158677857503732152612499548654948313017471839403896507493988578648,
        18631698991280989165794156185809282554249027473066654851015905870822852378043,
      ],
      [],
    ],
    pubkeys: [
      g1.decompress(
        #"968cc0fcd3879a0b7b1f1f70fe60a7c5ea3aa45fcbb2d4963c5dec7b9efa5ec23be6ebf59f285d904d734afdf2f0147e",
      ),
      g1.decompress(
        #"896b2e6fab0e737e1e299da5ea2cf9046883aaea3b4271bc0463f6cbe964be5b54f09325ee02caa704f7e71c03cd392a",
      ),
    ],
  }

pub fn check_vcerts(iproof: IssueProof, vcerts: List<Vcert>) -> Bool {
  let pks = iproof.pubkeys
  check_vcert_item(vcerts, pks)
}

fn check_vcert_item(vcerts: List<Vcert>, pks: List<G1Element>) -> Bool {
  let first_vcert = head(vcerts)
  let first_pk = head(pks)

  if is_none(first_vcert) {
    True
  } else {
    expect Some(first_vcert_) = first_vcert
    expect Some(first_pk_) = first_pk
    let check_result =
      do_ecdsa_verify(first_pk_, first_vcert_.signature, first_vcert_.commit)
    if check_result == False {
      False
    } else {
      let tail_vcerts = tail(vcerts)
      let tail_pks = tail(pks)
      expect Some(tail_vcerts_) = tail_vcerts
      expect Some(tail_pks_) = tail_pks
      check_vcert_item(tail_vcerts_, tail_pks_)
    }
  }
}

test check_vcerts_test() {
  let sign: Sign =
    Sign {
      r: 1405393218543153634611558277146205543651389828460482046569307751654236783901042705626443752376987448075822652265738,
      s: 38202479084295088188067894688129388712852808125955621239765113527621075572534,
      r_g1: g1.decompress(
        #"89218ac9d46dbef17651a764dd5e0ee7414b040221e3d0f188642129acfea1a17862de38851b2483095449c4732d150a",
      ),
    }
  let sign2: Sign =
    Sign {
      r: 2552680529624568173590066327177950774551146809542008094226796730622167382728536331628983497397925589240933200869214,
      s: 42372284252738667106345738865448192044614864058854813921958423275374058347560,
      r_g1: g1.decompress(
        #"9095c91e320d01fad00d33f26f19cfaa6e9d4a64a820bc2a854c72f3c72e3d47d55c418374daa130818e43c73a02b75e",
      ),
    }
  let commit1 =
    #"1669f6cef337b4373a0f3e6307c6cdfb44517a36e125d7866ee9e838f4f5455cca63ce114d25b62ae4e597dc78c4db45170d8abb0611028477e44388db31dccbee44f308b8f5cd934727ede4202b807fe1e7ba3c0d7c0680c9213dd84a29576d"
  let commit2 =
    #"08f174c5102f45f9a4becc60fd8561d5948240ca3494830f20c143b4e116902bf633ebab064d90b920394a1588636aba0e794a1e4e852485931858df9b034535078f94d6f68e4da286130dbef7d15d4cf5768718d703227c04dab741ef2b078e"
  check_vcerts(
    iproof,
    [
      Vcert { commit: commit1, signature: sign },
      Vcert { commit: commit2, signature: sign2 },
    ],
  ) == True
}
