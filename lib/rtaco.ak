use aiken/builtin.{
  bls12_381_final_verify, bls12_381_g1_add, bls12_381_g1_compress,
  bls12_381_g1_scalar_mul, bls12_381_g1_uncompress, bls12_381_g2_add,
  bls12_381_g2_compress, bls12_381_g2_hash_to_group, bls12_381_g2_scalar_mul,
  bls12_381_g2_uncompress, bls12_381_miller_loop,
  bls12_381_mul_miller_loop_result, bytearray_to_integer,
}
use aiken/collection/list.{foldl, head, length, range, tail}
use aiken/crypto.{sha2_256}
use aiken/crypto/bls12_381/g1 as g1
use aiken/crypto/bls12_381/g2 as g2
use aiken/crypto/bls12_381/scalar as scalar
use aiken/option.{is_none}
use aiken/primitive/bytearray.{concat}
use bls.{
  Sign, bytearray_big_endian_to_int, do_ecdsa_verify, g1_to_binary256,
  g2_to_binary256, list_g1_to_binary256,
}

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
  check_vcert_item(vcerts, pks) && check_sk(iproof)
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

pub fn check_sk(proof: IssueProof) -> Bool {
  let first_item = head(proof.total_rm)
  expect Some(first_item_) = first_item
  let first_item_index = head(first_item_)
  expect Some(first_item_index_) = first_item_index
  expect Some(tail_items) = tail(proof.total_rm)
  check_sk_item(first_item_index_, tail_items)
}

fn check_sk_item(first_item_index: Int, total_rm: List<List<Int>>) -> Bool {
  let first = head(total_rm)
  if is_none(first) {
    True
  } else {
    expect Some(first_) = first
    let first_index = head(first_)
    expect Some(first_index_) = first_index
    if first_index_ != first_item_index {
      False
    } else {
      let tail_rm = tail(total_rm)
      expect Some(tail_rm_) = tail_rm
      check_sk_item(first_item_index, tail_rm_)
    }
  }
}

pub fn check_issue_proof() {
  // G.G1Point[] memory Aw = calculate_Aw(name, proof.combination, compressed_params.commitments, cm, proof);
  //     G.G1Point memory Bw = calculate_Bw(name, proof.combination, cm, proof);
  //     G.G1Point[] memory Cw = calculate_Cw(proof.combination, vcerts, proof); 
  //     return (proof.c == ToChallengeIssue(cm, G.HashToPoint(uint256(G.G1_to_binary256(cm))), Bw, params.get_hs(name), Aw, Cw));
  todo
}

pub fn check_open_proof() {
  todo
}

pub fn request_cred() {
  todo
}

pub fn calculate_Aw(proof: IssueProof) -> List<G1Element> {
  let ros = proof.ros
  let total_rm = proof.total_rm
  todo
}

// Aw ['01c758c6592e7c909d591c9474410083b990e8f579212e426abdffdfc379eee14eaf19a32728b1ea547050a9f19a5b5c17dcebd20e4840c10bdf8c727767540bcdacbebe337dc19c24f6bf3b1d0ee673b2d09d84a3aff894e4ce4c0186d90596', '0636ceadb8ff4939d627876673252ecc80dfff9e24e8ad472d0c923aea64be003099b739fcdec1cf4a19863d1e1e8ad8042f0ce697b60fbee325480e35e7d53c1a53c3aee80757b0dbbca82d502d096a9280df278b0385dc31f89dc8c14fb1ac', '095367cfa196882df8158ca4a170aee2dad0de5aef5da35cce68df0fd3d84fee802db2d9515fa0f533dfe877b99b873f179720b5d1d1b201b97cd205f544ce78f32140f94d5c0ce05c0ffa4a60a51887ac6a155affc8a328ef038fd9c67aa802', '03dd31367b0043ac3b5e388c5fbd444306fc2fa50530ba85a6959814a8018cc42d7849e89a8510708b71913deb592a5b0698277352591ac2ba960d24549ccca502bb5d0f7a966d87943f06e83ca1c16d523d9e9eee8d6902a65970711fb4b6d4']
// Bw 0eab76340ac0fce95d65bfb0b43b56dcbd75bc61eacac548743dbbeb3d808fc8280b5d18a44287f7893dec7a88ed192405c44f0ddaba5a347aecb20dd713c9cb4273752043b5de0aa4a35a57065c042abe549adbf0ed8bcd62cbee71991a3e5b
// Cw ['18baae4658a9665920a133f51e484292e0ccae4d9e1cd3b4ad2ba6b777da44c3848d756d0344780512c3fa3c5588353d0b749666b9f82e8e21d2c988d14503355b1973e002fce6e7996f1f32738965bb48d63e8c889771b440d9b5ad79854b75', '14f7384cc443d6da975f1455edf984329bee9ba75ad9ef88c5c0ad5b7723ff7656f7023bbcb6dea29f61f72785e27d2c008a8dd1e5007767545c20607ce36cde53bc64e7406829b10d96a10841997adfda1903f3472ad50757ccbd65cfb9c07f']
// g1 17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1
// g2 ['024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb813e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e', '0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b828010606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be']
// cm 16f4560bf6208523870c55aa4ac97b38ce3dbcc7d1e60c7935b5e55915afaa01b5f475db5dce8b2e274fd0b734c7d38c16b54a0f2bf27eb093eb42567e616046c1dfbc3438fb527db164cd39b81044e74383b23043d911cac5a619924d5eccff
// h 12ff779ca398381a210c60304207437607a3173332ae56365f8172f390aa0981c948260503b1604db62e0cfcf78f94a50dbee28343d610eff156fb8e3c393b983cecb1ea65d960eaa2f1a4946243540f8f832924b77a896331df0c895f17fe76
// hs ['0090cfe9261fdcfbe1b0b3f74256e57f6a5bdd98c13b0e09f9484838b02239a0ab8b883b7910585c13918f995eb8df891655908d3acb820cfcd2b69aa43c6df453bfb957fb8b6dd4dc477c5b7d43cc93d9746c0c3d1a8c8f32876d08aed48ee8', '065341b6a4affbe3b795d2d3c71781ad7267849fe2b24e728e13524d60d08e5a1681344b20268ea337d2fa2c1c3bbd7c025278d0bb80f8ccde8dfdbabf5f47a1249923e9e1e6e2b21df08781ed6cdc10947dfd51301e0c67ce724ca7d70841ef', '0e1dc44ad2d3084be3574e5feb59476b1c530322c1eab7d9a869372899cdfa75279ff5119ca6d2980e9e022a98a0ba6b16c3b8d1513387714a0febf64bdac7c2cabd3e07828a8793118f4a5c52f4492ebec48ea4e992c3022706bbcaf7eaf2e2', '1358409e76fa35a23ec6f3e88bd963eb9da3ad83e59e3c005a3b4e050061fda1fe56227dcec8610061073795fb259b5014d7a833b904c59be96015957f7cf97efd49dc61f54654a29223853d635ba465c91faf3e03f7abbabcd0fb7d4457c248', '0bb97519cdb28bb8ceab19bb289c02856a542da4ce52fd3c2cbe8914986f7162a2632e94a6420e47c3d7503f2024fb3d04814cc4d389d20599620a1a9f1adb3497b06434d39fcdd0e886b50fd750a87375e466393c587e6f52a034a576cd95be', '0d06e182789336765f00589a3dd16690ad368d656e95a4b7709bb7ba686d17ae7df5f23e91270bccf334632b3c86df9904384131406f288bc275cfe2ea683130b2867e3f960e1065f3a777b0a9f16ac07805790a4c797d080e325fa13abf8d6d', '194278e9661d267e2eaec3fee0a9302fc58347be0466778ea4ba55c9ca426a9856ef7479fc381e7408a9e01da5cc24de02b410d38dc25307f1741568f84700e4ddf6af326631024d34327279e909383c0c0b3061ee6068225c21186c4a164e4e']
// c 114250197776674931772775938331885352381527492900329639230266922666320756378329

pub fn to_challenge_issue(
  g1: ByteArray,
  g2: List<ByteArray>,
  cm: ByteArray,
  h: ByteArray,
  bw: ByteArray,
  hs: List<ByteArray>,
  aw: List<ByteArray>,
  cw: List<ByteArray>,
) -> ByteArray {
  let g1_bytes = g1_to_binary256(g1)
  let g2_first = head(g2)
  let g2_tail = tail(g2)
  expect Some(g2_tail_) = g2_tail
  let g2_second = head(g2_tail_)
  expect Some(g2_first_) = g2_first
  expect Some(g2_second_) = g2_second
  let g2_bytes = g2_to_binary256(g2_first_, g2_second_)
  let cm_bytes = g1_to_binary256(cm)
  let h_bytes = g1_to_binary256(h)
  let bw_bytes = g1_to_binary256(bw)
  let hs_bytes = list_g1_to_binary256(hs)
  let aw_bytes = list_g1_to_binary256(aw)
  let cw_bytes = list_g1_to_binary256(cw)
  let first_c = concat(g1_bytes, g2_bytes)
  let second_c = concat(first_c, cm_bytes)
  let third_c = concat(second_c, h_bytes)
  let fourth_c = concat(third_c, bw_bytes)
  let fifth_c = concat(fourth_c, hs_bytes)
  let sixth_c = concat(fifth_c, aw_bytes)
  let seventh_c = concat(sixth_c, cw_bytes)
  sha2_256(seventh_c)
}

test to_challenge_issue_test() {
  let g1 =
    #"17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"
  let g2 =
    [
      #"024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb813e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e",
      #"0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b828010606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be",
    ]
  let cm =
    #"16f4560bf6208523870c55aa4ac97b38ce3dbcc7d1e60c7935b5e55915afaa01b5f475db5dce8b2e274fd0b734c7d38c16b54a0f2bf27eb093eb42567e616046c1dfbc3438fb527db164cd39b81044e74383b23043d911cac5a619924d5eccff"
  let h =
    #"12ff779ca398381a210c60304207437607a3173332ae56365f8172f390aa0981c948260503b1604db62e0cfcf78f94a50dbee28343d610eff156fb8e3c393b983cecb1ea65d960eaa2f1a4946243540f8f832924b77a896331df0c895f17fe76"
  let bw =
    #"0eab76340ac0fce95d65bfb0b43b56dcbd75bc61eacac548743dbbeb3d808fc8280b5d18a44287f7893dec7a88ed192405c44f0ddaba5a347aecb20dd713c9cb4273752043b5de0aa4a35a57065c042abe549adbf0ed8bcd62cbee71991a3e5b"
  let hs =
    [
      #"0090cfe9261fdcfbe1b0b3f74256e57f6a5bdd98c13b0e09f9484838b02239a0ab8b883b7910585c13918f995eb8df891655908d3acb820cfcd2b69aa43c6df453bfb957fb8b6dd4dc477c5b7d43cc93d9746c0c3d1a8c8f32876d08aed48ee8",
      #"065341b6a4affbe3b795d2d3c71781ad7267849fe2b24e728e13524d60d08e5a1681344b20268ea337d2fa2c1c3bbd7c025278d0bb80f8ccde8dfdbabf5f47a1249923e9e1e6e2b21df08781ed6cdc10947dfd51301e0c67ce724ca7d70841ef",
      #"0e1dc44ad2d3084be3574e5feb59476b1c530322c1eab7d9a869372899cdfa75279ff5119ca6d2980e9e022a98a0ba6b16c3b8d1513387714a0febf64bdac7c2cabd3e07828a8793118f4a5c52f4492ebec48ea4e992c3022706bbcaf7eaf2e2",
      #"1358409e76fa35a23ec6f3e88bd963eb9da3ad83e59e3c005a3b4e050061fda1fe56227dcec8610061073795fb259b5014d7a833b904c59be96015957f7cf97efd49dc61f54654a29223853d635ba465c91faf3e03f7abbabcd0fb7d4457c248",
      #"0bb97519cdb28bb8ceab19bb289c02856a542da4ce52fd3c2cbe8914986f7162a2632e94a6420e47c3d7503f2024fb3d04814cc4d389d20599620a1a9f1adb3497b06434d39fcdd0e886b50fd750a87375e466393c587e6f52a034a576cd95be",
      #"0d06e182789336765f00589a3dd16690ad368d656e95a4b7709bb7ba686d17ae7df5f23e91270bccf334632b3c86df9904384131406f288bc275cfe2ea683130b2867e3f960e1065f3a777b0a9f16ac07805790a4c797d080e325fa13abf8d6d",
      #"194278e9661d267e2eaec3fee0a9302fc58347be0466778ea4ba55c9ca426a9856ef7479fc381e7408a9e01da5cc24de02b410d38dc25307f1741568f84700e4ddf6af326631024d34327279e909383c0c0b3061ee6068225c21186c4a164e4e",
    ]
  let aw =
    [
      #"01c758c6592e7c909d591c9474410083b990e8f579212e426abdffdfc379eee14eaf19a32728b1ea547050a9f19a5b5c17dcebd20e4840c10bdf8c727767540bcdacbebe337dc19c24f6bf3b1d0ee673b2d09d84a3aff894e4ce4c0186d90596",
      #"0636ceadb8ff4939d627876673252ecc80dfff9e24e8ad472d0c923aea64be003099b739fcdec1cf4a19863d1e1e8ad8042f0ce697b60fbee325480e35e7d53c1a53c3aee80757b0dbbca82d502d096a9280df278b0385dc31f89dc8c14fb1ac",
      #"095367cfa196882df8158ca4a170aee2dad0de5aef5da35cce68df0fd3d84fee802db2d9515fa0f533dfe877b99b873f179720b5d1d1b201b97cd205f544ce78f32140f94d5c0ce05c0ffa4a60a51887ac6a155affc8a328ef038fd9c67aa802",
      #"03dd31367b0043ac3b5e388c5fbd444306fc2fa50530ba85a6959814a8018cc42d7849e89a8510708b71913deb592a5b0698277352591ac2ba960d24549ccca502bb5d0f7a966d87943f06e83ca1c16d523d9e9eee8d6902a65970711fb4b6d4",
    ]
  let cw =
    [
      #"18baae4658a9665920a133f51e484292e0ccae4d9e1cd3b4ad2ba6b777da44c3848d756d0344780512c3fa3c5588353d0b749666b9f82e8e21d2c988d14503355b1973e002fce6e7996f1f32738965bb48d63e8c889771b440d9b5ad79854b75",
      #"14f7384cc443d6da975f1455edf984329bee9ba75ad9ef88c5c0ad5b7723ff7656f7023bbcb6dea29f61f72785e27d2c008a8dd1e5007767545c20607ce36cde53bc64e7406829b10d96a10841997adfda1903f3472ad50757ccbd65cfb9c07f",
    ]
  let c =
    114250197776674931772775938331885352381527492900329639230266922666320756378329
  let challage = to_challenge_issue(g1, g2, cm, h, bw, hs, aw, cw)
  trace bytearray_big_endian_to_int(challage)
  expect c == bytearray_big_endian_to_int(challage)
}
