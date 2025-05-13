use aiken/collection/list.{head, tail}
use aiken/crypto.{sha2_256}
use aiken/crypto/bls12_381/g1 as g1
use aiken/option.{is_none}
use aiken/primitive/bytearray.{concat}
use aiken/primitive/int.{from_bytearray_big_endian}
use bls.{
  Sign, do_ecdsa_verify, g1_to_binary256, g2_to_binary256, list_g1_to_binary256,
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

pub fn check_issue_proof(
  g1: ByteArray,
  g2: List<ByteArray>,
  cm: ByteArray,
  h: ByteArray,
  bw: ByteArray,
  hs: List<ByteArray>,
  aw: List<ByteArray>,
  cw: List<ByteArray>,
  proof: IssueProof,
) {
  // G.G1Point[] memory Aw = calculate_Aw(name, proof.combination, compressed_params.commitments, cm, proof);
  //     G.G1Point memory Bw = calculate_Bw(name, proof.combination, cm, proof);
  //     G.G1Point[] memory Cw = calculate_Cw(proof.combination, vcerts, proof); 
  //     return (proof.c == ToChallengeIssue(cm, G.HashToPoint(uint256(G.G1_to_binary256(cm))), Bw, params.get_hs(name), Aw, Cw));
  proof.c == from_bytearray_big_endian(
    to_challenge_issue(g1, g2, cm, h, bw, hs, aw, cw),
  )
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
  trace g1_bytes
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

// Aw ['166241f947b01106dc59ea1fe8e3df1309fcb1fcfa094ae246021a2b56e4e8776dc34ac7ec92b2d12ea1a5267e4acde2006d8549d511ace2d2bf6af0ea9fc203cb9e155049868b4b7dbfe82d0e5cc56fcbff573d662aba87ec8bad96578ebd75', '0541d95c30d9f26feb7d045d4eb00e9abce4b64cb9a3a4f2aa17d72fa7191ff30acb5ec52b0fc207212368b5264da9010fd34454ed4e80cd029563db444f5f49380d2be3d75f6c0ed722313ce5b1e8f385d07e95b5a766750ecf9036afbea4d6', '116e20c73c34e537550c82965d8827ce6e56a0256d5951069fd4a21b177114ab0f12b9b5031924e2cfafdb645c1361c019dac88947992a883289ebb02e9599308d5c44d640476543992d4ea1c6d61572afb592f0df3e8790fbf9ebbe3b13c7a1', '0f9fcb3f72dacc753252ac8f394522180d8789b47571d03169f2c652e4a3c1680cbb58f265b6280264b6a3cc27991c5714d34345913ef131f49c0d3114d4cf84540cf88ec29b67e964188d0e6686aaad146b38af8d0d4f4d74f1f30843f4748d']
// Bw 1705263a9cc42459ec795eab378681c21529f1caebc75b4942f7bc4f04b745c74faaa9147e54d24a6919f54f724239c1164af1fd1ac4a2ff8529de30a907fa51175367b4da543030deda7723f47305705561bad5758291105d2543146ce1c2c3
// Cw ['16519e13edea4fe7472ccb1eb8c084e0ad6549341c90e5e9d3e731c5cebbc19997a026cdaec7005ce4bcb102f3000967026f2b2262e3a5b113a7042af2966e29bf180d31ec971b81c737996fa2114a0a0c7d2f784d829936818459c63432c7a6', '0a4b1e237cb18d6bc03ed00efd7e7ddc18229fe35ebc3191594969e884874e9fe31d87065b033f23d0bb7f882aee0fca082a0eff7c55972156113c5917adbf04beb9784c535e3f99cf1bd6a72ea4d9c93e4cb48ee3f0f99bd0f3ab69b899f2e4']
// g1 17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1
// g2 ['024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb813e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e', '0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b828010606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be']
// cm 0a52d3212c09ef8aa23574c8ff1ea9c3d8b531bf67b75747ea80398a628185063e15065a80a4e17b9b5ec24088d46e550ac9f02f6a9831ccff01860cd0bbaad22ddbcf283832cbddd2b4bf830e0655334e9ec7c50688718ef6080274114becf4
// h 0478274c35d83186d1ccd6a83369e4bd3e19daecda41beba0ffa3f32dc187dc38dda71b7b4b2080b4d2c408678e769fc0ac142467746328ebad4414aca141f580f4c36e017c73e109e34261ce22ea84b9ad0ec675bc0852fea8938fe1611fb91
// hs ['0090cfe9261fdcfbe1b0b3f74256e57f6a5bdd98c13b0e09f9484838b02239a0ab8b883b7910585c13918f995eb8df891655908d3acb820cfcd2b69aa43c6df453bfb957fb8b6dd4dc477c5b7d43cc93d9746c0c3d1a8c8f32876d08aed48ee8', '065341b6a4affbe3b795d2d3c71781ad7267849fe2b24e728e13524d60d08e5a1681344b20268ea337d2fa2c1c3bbd7c025278d0bb80f8ccde8dfdbabf5f47a1249923e9e1e6e2b21df08781ed6cdc10947dfd51301e0c67ce724ca7d70841ef', '0e1dc44ad2d3084be3574e5feb59476b1c530322c1eab7d9a869372899cdfa75279ff5119ca6d2980e9e022a98a0ba6b16c3b8d1513387714a0febf64bdac7c2cabd3e07828a8793118f4a5c52f4492ebec48ea4e992c3022706bbcaf7eaf2e2', '1358409e76fa35a23ec6f3e88bd963eb9da3ad83e59e3c005a3b4e050061fda1fe56227dcec8610061073795fb259b5014d7a833b904c59be96015957f7cf97efd49dc61f54654a29223853d635ba465c91faf3e03f7abbabcd0fb7d4457c248', '0bb97519cdb28bb8ceab19bb289c02856a542da4ce52fd3c2cbe8914986f7162a2632e94a6420e47c3d7503f2024fb3d04814cc4d389d20599620a1a9f1adb3497b06434d39fcdd0e886b50fd750a87375e466393c587e6f52a034a576cd95be', '0d06e182789336765f00589a3dd16690ad368d656e95a4b7709bb7ba686d17ae7df5f23e91270bccf334632b3c86df9904384131406f288bc275cfe2ea683130b2867e3f960e1065f3a777b0a9f16ac07805790a4c797d080e325fa13abf8d6d', '194278e9661d267e2eaec3fee0a9302fc58347be0466778ea4ba55c9ca426a9856ef7479fc381e7408a9e01da5cc24de02b410d38dc25307f1741568f84700e4ddf6af326631024d34327279e909383c0c0b3061ee6068225c21186c4a164e4e']
// c 90889679917086702897764874634553305957805027920137946837610029982752513678276

test to_challenge_issue_test() {
  let g1 =
    #"17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"
  let g2 =
    [
      #"024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb813e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e",
      #"0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b828010606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be",
    ]
  let cm =
    #"0a52d3212c09ef8aa23574c8ff1ea9c3d8b531bf67b75747ea80398a628185063e15065a80a4e17b9b5ec24088d46e550ac9f02f6a9831ccff01860cd0bbaad22ddbcf283832cbddd2b4bf830e0655334e9ec7c50688718ef6080274114becf4"
  let h =
    #"0478274c35d83186d1ccd6a83369e4bd3e19daecda41beba0ffa3f32dc187dc38dda71b7b4b2080b4d2c408678e769fc0ac142467746328ebad4414aca141f580f4c36e017c73e109e34261ce22ea84b9ad0ec675bc0852fea8938fe1611fb91"
  let bw =
    #"1705263a9cc42459ec795eab378681c21529f1caebc75b4942f7bc4f04b745c74faaa9147e54d24a6919f54f724239c1164af1fd1ac4a2ff8529de30a907fa51175367b4da543030deda7723f47305705561bad5758291105d2543146ce1c2c3"
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
      #"166241f947b01106dc59ea1fe8e3df1309fcb1fcfa094ae246021a2b56e4e8776dc34ac7ec92b2d12ea1a5267e4acde2006d8549d511ace2d2bf6af0ea9fc203cb9e155049868b4b7dbfe82d0e5cc56fcbff573d662aba87ec8bad96578ebd75",
      #"0541d95c30d9f26feb7d045d4eb00e9abce4b64cb9a3a4f2aa17d72fa7191ff30acb5ec52b0fc207212368b5264da9010fd34454ed4e80cd029563db444f5f49380d2be3d75f6c0ed722313ce5b1e8f385d07e95b5a766750ecf9036afbea4d6",
      #"116e20c73c34e537550c82965d8827ce6e56a0256d5951069fd4a21b177114ab0f12b9b5031924e2cfafdb645c1361c019dac88947992a883289ebb02e9599308d5c44d640476543992d4ea1c6d61572afb592f0df3e8790fbf9ebbe3b13c7a1",
      #"0f9fcb3f72dacc753252ac8f394522180d8789b47571d03169f2c652e4a3c1680cbb58f265b6280264b6a3cc27991c5714d34345913ef131f49c0d3114d4cf84540cf88ec29b67e964188d0e6686aaad146b38af8d0d4f4d74f1f30843f4748d",
    ]
  let cw =
    [
      #"16519e13edea4fe7472ccb1eb8c084e0ad6549341c90e5e9d3e731c5cebbc19997a026cdaec7005ce4bcb102f3000967026f2b2262e3a5b113a7042af2966e29bf180d31ec971b81c737996fa2114a0a0c7d2f784d829936818459c63432c7a6",
      #"0a4b1e237cb18d6bc03ed00efd7e7ddc18229fe35ebc3191594969e884874e9fe31d87065b033f23d0bb7f882aee0fca082a0eff7c55972156113c5917adbf04beb9784c535e3f99cf1bd6a72ea4d9c93e4cb48ee3f0f99bd0f3ab69b899f2e4",
    ]
  let c =
    90889679917086702897764874634553305957805027920137946837610029982752513678276
  let challenge = to_challenge_issue(g1, g2, cm, h, bw, hs, aw, cw)
  trace challenge
  expect
    #"c8f1bc5dd31ee1f58da9c4541c1ed9fd258476d74ba2e145a8b25596685f5bc4" == challenge
  expect c == from_bytearray_big_endian(challenge)
}

// G1
// 17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1
// b1fbe330769a11acc36fc723335b0220323273e006f2b6fdb9db39ea82e7c183

test test_g1_hash() {
  let g1 =
    #"17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"
  let g1_hash = g1_to_binary256(g1)
  trace g1_hash
  expect
    g1_hash == #"b1fbe330769a11acc36fc723335b0220323273e006f2b6fdb9db39ea82e7c183"
}

test test_g1_hash_2() {
  let g1 =
    #"0090cfe9261fdcfbe1b0b3f74256e57f6a5bdd98c13b0e09f9484838b02239a0ab8b883b7910585c13918f995eb8df891655908d3acb820cfcd2b69aa43c6df453bfb957fb8b6dd4dc477c5b7d43cc93d9746c0c3d1a8c8f32876d08aed48ee8"
  let g1_hash = g1_to_binary256(g1)
  trace g1_hash
  expect
    g1_hash == #"b95e27b84bcc547b495e0b233aecb9b7b3e4cd5be806ed8315bc50c3a8dd9a24"
}
