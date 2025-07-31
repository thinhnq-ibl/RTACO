use aiken/collection/list.{head, tail}
use aiken/crypto.{sha2_256}
use aiken/crypto/bls12_381/g1 as g1
use aiken/crypto/bls12_381/g2 as g2
use aiken/crypto/bls12_381/scalar
use aiken/option.{is_none}
use aiken/primitive/bytearray.{concat}
use aiken/primitive/int.{from_bytearray_big_endian}
use bls.{
  Sign, do_ecdsa_verify, g1_to_binary256, g2_to_binary256, list_bytearray_to_g1,
  list_compressed_to_g1, list_compressed_to_g2, list_g1_to_binary256,
}

pub type Vcert {
  // G1 point
  commit: ByteArray,
  // Sign struct
  signature: Sign,
}

pub type IssueProof {
  c: Int,
  rr: Int,
  ros: List<Int>,
  total_rm: List<List<Int>>,
  pubkeys: List<ByteArray>,
}

pub type OpenProof {
  // g2 point list
  dw: List<ByteArray>,
  // g2 point list
  ew: List<ByteArray>,
  c: List<Int>,
  sigma: List<ByteArray>,
}

pub fn check_vcerts(iproof: IssueProof, vcerts: List<Vcert>) -> Bool {
  let pks = iproof.pubkeys
  let decompress_pks = list_compressed_to_g1(pks)
  check_vcert_item(vcerts, decompress_pks) && check_sk(iproof)
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
      trace first_vcert_.commit
      False
    } else {
      expect Some(tail_vcerts_) = tail(vcerts)
      expect Some(tail_pks_) = tail(pks)
      check_vcert_item(tail_vcerts_, tail_pks_)
    }
  }
}

test check_vcerts_test() {
  let iproof =
    IssueProof {
      c: 48283155021403692803625869534801594269864565675904435442702469331345732239617,
      rr: 36531052383402211828359274919355994021648640115154246849979944583449255146219,
      ros: [
        36418807606724627941935870713643053093391568771381577466124394849968709623379,
        20160247163736695635061499260001451057044996851971626202048713041795764662913,
      ],
      total_rm: [
        [
          21547953939306548461728894630797256592572300260822873296306957243377041888642,
          9811558232841658896503110917654297146358527082355640657963557141391689166169,
          12493290798263166147703308517255258971231540024900190747885335861750537531501,
          19891087659639807919471394933505082450697170899983429432006297224132669366975,
        ],
        [
          21547953939306548461728894630797256592572300260822873296306957243377041888642,
          38749844156253605985945579121185330537885135274723186087163255293074452059721,
          35378189200517590899483254299855791372851781463319077371129846583617003982916,
        ],
        [],
      ],
      pubkeys: [
        #"a97b2135da7799823236baea87402c5cc00e3a61c99e9abf7c2d9c0c29d1c50fd5753e3076c5e3da091c861199ee72b7",
        #"b51cc7408bc47ad537c29fef899a73b784de41c2063d5aac5248623f3db3dd4131e1cd9af902d49b28bc38819ffb48eb",
      ],
    }

  let sign: Sign =
    Sign {
      r: 1947564745249895947708144629914312558157305610980073189304752255321217468940983390413315295194393892376039785033790,
      s: 17355617863143591184525546256817223357573510192270296979117455415910592064385,
      r_g1: #"aca7513f4288ab39cdb45202f54678d9bd5d815b52295dc7f22b16c7572e13b93d96b6837288a909d801ce61a638f03e",
    }

  let sign2: Sign =
    Sign {
      r: 3924284939951961681834764047095286118299427666162894647982549458393534809915388538121180076697345644595416192308475,
      s: 30161833219843676097829195363654408677477538928028790969163359605163750361918,
      r_g1: #"b97f20c47b4d12e53f6cb898067b63532e53c906b200f2638db569a7d50977a7fbb53609e324b65a9934b3d08960d4fb",
    }
  let commit1 =
    #"075320f826a216c87da892bfc8aaacd2a75f5ccdfa62b72de3491b0bf079201a2def1fc9f18234df324976fdaf267870112bdf0ec3b461ae5bf50d9d0cde259cfdaa4789a6a7595dc3a37a76d6bc7c11d14cfb7528a60ea753bba5e501af4d5a"
  let commit2 =
    #"03324843cb50de5ba1dc8202d2f122a079857340727e63ad1227c3c9068acbd6039d452a6cf8b49405bd895c528582f319de1c7c436db928c356fc685aa32832ade4583760476d176f366c0fd5b92d4b93256afd144d2f815abd721d497d2aee"
  check_vcerts(
    iproof,
    [
      Vcert { commit: commit1, signature: sign },
      Vcert { commit: commit2, signature: sign2 },
    ],
  ) == True
}

pub fn check_sk(proof: IssueProof) -> Bool {
  expect Some(first_item_) = head(proof.total_rm)
  expect Some(first_item_index_) = head(first_item_)
  expect Some(tail_items) = tail(proof.total_rm)
  check_sk_item(first_item_index_, tail_items)
}

fn check_sk_item(first_item_index: Int, total_rm: List<List<Int>>) -> Bool {
  let first = head(total_rm)
  if is_none(first) {
    True
  } else {
    expect Some(first_) = first
    if list.is_empty(first_) {
      // If the first item is empty, we can skip it
      True
    } else {
      expect Some(first_index_) = head(first_)
      if first_index_ != first_item_index {
        False
      } else {
        expect Some(tail_rm_) = tail(total_rm)
        check_sk_item(first_item_index, tail_rm_)
      }
    }
  }
}

pub fn check_issue_proof(
  cm_compressed: ByteArray,
  h_compressed: ByteArray,
  hs_compressed: List<ByteArray>,
  commits_compressed: List<ByteArray>,
  proof: IssueProof,
  rm: List<Int>,
) {
  let commits = list_bytearray_to_g1(commits_compressed)
  let hs = list_bytearray_to_g1(hs_compressed)
  let h = g1.decompress(h_compressed)
  let cm = g1.decompress(cm_compressed)
  let aw = calculate_Aw(commits, proof.c, proof.ros, h, rm)
  let bw = calculate_Bw(proof.c, proof.rr, rm, cm, hs)
  let cw = calculate_Cw(proof.total_rm, commits, proof.c, hs)
  proof.c == from_bytearray_big_endian(
    to_challenge_issue(cm, h, bw, hs, aw, cw),
  )
}

pub fn get_rm(
  total_rm: List<List<Int>>,
  include_indexes: List<List<Int>>,
) -> List<Int> {
  let first = head(total_rm)
  if is_none(first) {
    []
  } else {
    expect Some(first_) = first
    expect Some(first_include_indexes_) = head(include_indexes)
    expect Some(tail_rm) = tail(total_rm)
    expect Some(tail_include_indexes) = tail(include_indexes)
    list.concat(
      get_rm_inner_item(first_, first_include_indexes_),
      get_rm(tail_rm, tail_include_indexes),
    )
  }
}

pub fn get_rm_inner_item(
  total_rm_inner_item: List<Int>,
  include_indexes_inner_item: List<Int>,
) -> List<Int> {
  let first = head(total_rm_inner_item)
  if is_none(first) {
    []
  } else {
    expect Some(first_) = first
    expect Some(first_included_) = head(include_indexes_inner_item)
    // tail
    expect Some(tail_rm) = tail(total_rm_inner_item)
    expect Some(tail_include_indexes) = tail(include_indexes_inner_item)
    if first_included_ == 1 {
      list.push(get_rm_inner_item(tail_rm, tail_include_indexes), first_)
    } else {
      get_rm_inner_item(tail_rm, tail_include_indexes)
    }
  }
}

pub fn request_cred(
  proof: IssueProof,
  open_proof: OpenProof,
  vcerts: List<Vcert>,
  cm_compressed: ByteArray,
  h_compressed: ByteArray,
  hs_compressed: List<ByteArray>,
  include_indexes: List<List<Int>>,
) {
  let rm = get_rm(proof.total_rm, include_indexes)
  let commits = get_commits(vcerts)
  let result1 = check_vcerts(proof, vcerts)
  let result2 =
    check_issue_proof(
      cm_compressed,
      h_compressed,
      hs_compressed,
      commits,
      proof,
      rm,
    )
  expect Some(h_) = head(open_proof.sigma)
  let result3 = check_open_proof(h_, hs_compressed, open_proof)
  result1 && result2 && result3
}

pub fn check_open_proof(
  h_compressed: ByteArray,
  hs_compressed: List<ByteArray>,
  proof: OpenProof,
) {
  let hs = list_compressed_to_g1(hs_compressed)
  let h = g1.decompress(h_compressed)
  let dw = list_compressed_to_g2(proof.dw)
  let ew = list_compressed_to_g2(proof.ew)
  check_open_challenge_item(h, hs, proof.c, dw, ew)
}

pub fn check_open_challenge_item(
  h: G1Element,
  hs: List<G1Element>,
  c: List<Int>,
  dw: List<G2Element>,
  ew: List<G2Element>,
) -> Bool {
  let dw_head = head(dw)
  if is_none(dw_head) {
    True
  } else {
    expect Some(dw_) = dw_head
    expect Some(ew_) = head(ew)
    expect Some(c_) = head(c)
    if c_ == from_bytearray_big_endian(to_challenge_open(h, dw_, ew_, hs)) {
      expect Some(tail_dw) = tail(dw)
      expect Some(tail_ew) = tail(ew)
      expect Some(tail_c) = tail(c)
      check_open_challenge_item(h, hs, tail_c, tail_dw, tail_ew)
    } else {
      False
    }
  }
}

fn get_commits(vcerts: List<Vcert>) -> List<ByteArray> {
  let first = head(vcerts)
  if is_none(first) {
    []
  } else {
    expect Some(first_) = first
    let commit_ = first_.commit
    expect Some(tail_) = tail(vcerts)
    let tail_commits = get_commits(tail_)
    list.push(tail_commits, commit_)
  }
}

pub fn calculate_Aw(
  commitments: List<G1Element>,
  c: Int,
  ros: List<Int>,
  h_point: G1Element,
  rm: List<Int>,
) -> List<G1Element> {
  calculate_Aw_item(commitments, c, ros, h_point, rm)
}

pub fn calculate_Aw_item(
  commitments: List<G1Element>,
  c: Int,
  ros: List<Int>,
  h_point: G1Element,
  rm: List<Int>,
) -> List<G1Element> {
  let head_commitments = head(commitments)
  if is_none(head_commitments) {
    []
  } else {
    expect Some(commitment) = head_commitments
    expect Some(head_ros_) = head(ros)
    expect Some(head_rm_) = head(rm)
    expect Some(c_sca) = scalar.new(c)
    expect Some(ros_sca) = scalar.new(head_ros_)
    let cal_ro = g1.scale(g1.generator, ros_sca)
    expect Some(rm_sca) = scalar.new(head_rm_)
    let cal_rm = g1.scale(h_point, rm_sca)
    let aw_item = g1.add(g1.scale(commitment, c_sca), g1.add(cal_ro, cal_rm))
    expect Some(tail_commitments_) = tail(commitments)
    expect Some(tail_ros_) = tail(ros)
    expect Some(tail_rm_) = tail(rm)
    let tail_result =
      calculate_Aw_item(tail_commitments_, c, tail_ros_, h_point, tail_rm_)
    list.push(tail_result, aw_item)
  }
}

pub fn calculate_Bw(
  c: Int,
  rr: Int,
  rm: List<Int>,
  cm_point: G1Element,
  hs: List<G1Element>,
) -> G1Element {
  expect Some(c_sca) = scalar.new(c)
  expect Some(rr_sca) = scalar.new(rr)
  let bw = g1.add(g1.scale(cm_point, c_sca), g1.scale(g1.generator, rr_sca))
  calculate_Bw_item(bw, rm, hs)
}

pub fn calculate_Bw_item(
  bw: G1Element,
  rm: List<Int>,
  hs: List<G1Element>,
) -> G1Element {
  let head_rm = head(rm)
  if is_none(head_rm) {
    bw
  } else {
    expect Some(head_rm_) = head_rm
    expect Some(head_hs_) = head(hs)
    expect Some(rm_sca) = scalar.new(head_rm_)
    let cal_rm = g1.scale(head_hs_, rm_sca)
    expect Some(tail_rm_) = tail(rm)
    expect Some(tail_hs_) = tail(hs)
    calculate_Bw_item(g1.add(bw, cal_rm), tail_rm_, tail_hs_)
  }
}

pub fn calculate_Cw(
  total_rm: List<List<Int>>,
  commits: List<G1Element>,
  c: Int,
  hs: List<G1Element>,
) -> List<G1Element> {
  calculate_Cw_item(total_rm, commits, c, hs)
}

pub fn calculate_Cw_item(
  total_rm: List<List<Int>>,
  commits: List<G1Element>,
  c: Int,
  hs: List<G1Element>,
) -> List<G1Element> {
  let first = head(total_rm)
  if is_none(first) {
    []
  } else {
    expect Some(first_) = first
    expect Some(commit_index_) = head(commits)
    expect Some(c_sca) = scalar.new(c)
    let tmp = g1.scale(commit_index_, c_sca)
    expect Some(last_first_) = list.last(first_)
    expect Some(init_first_) = list.init(first_)
    expect Some(last_first_scalar) = scalar.new(last_first_)
    let updated_tmp = g1.add(tmp, g1.scale(g1.generator, last_first_scalar))
    let first_item = calculate_Cw_hs(updated_tmp, hs, init_first_)
    expect Some(tail_rm_) = tail(total_rm)
    expect Some(tail_commits_) = tail(commits)
    let tail_result = calculate_Cw_item(tail_rm_, tail_commits_, c, hs)
    list.push(tail_result, first_item)
  }
}

pub fn calculate_Cw_hs(
  tmp: G1Element,
  hs: List<G1Element>,
  total_rm_elemnt: List<Int>,
) -> G1Element {
  let first = head(total_rm_elemnt)
  if is_none(first) {
    tmp
  } else {
    expect Some(first_) = first
    expect Some(first_hs_) = head(hs)
    expect Some(first_hs_sca) = scalar.new(first_)
    let sum_f = g1.add(tmp, g1.scale(first_hs_, first_hs_sca))
    expect Some(tail_rm_) = tail(total_rm_elemnt)
    expect Some(tail_hs_) = tail(hs)
    calculate_Cw_hs(sum_f, tail_hs_, tail_rm_)
  }
}

pub fn to_challenge_issue(
  cm: G1Element,
  h: G1Element,
  bw: G1Element,
  hs: List<G1Element>,
  aw: List<G1Element>,
  cw: List<G1Element>,
) -> ByteArray {
  let g1_bytes = g1_to_binary256(g1.generator)
  let g2_bytes = g2_to_binary256(g2.generator)
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
  let aw =
    [
      #"b979267a148f3329bb962656aef1fe9bc493c15783e0ecdfbcd0995211dd3914732a2c36fc27966de4a94b8c2f7a4d02",
      #"ae13b11baa3920f8aa906bc559814d49d77728b8be1117f59319b644334ecd73d790d3d129c5c7418fdebe694219766a",
      #"8f920ca30e4b357e1c34e4e8d69c7b8917b4e2ec1be67f36475e88bd7bc889b6c6dcee7c37bb2ad0f216bd908dd27cce",
      #"8291c2f8b2f3666945b16c9c09355b2f6776f4104c3463aed549e167ff75b1ca9ee35b19da77c4aec0a23190e90de3d0",
    ]
  let bw =
    #"aa4059ef3e1deb52efb84e368e5d9af61481b9a1a18180893a54e4f339a209094e5f5c45126ab7e61a116cbe6a27d75f"
  let cw =
    [
      #"ac70d9b947a396efc552b4797c7c0b397f1e54f6d91dd720a1812aeb8764510bca3a760bf49c8558503f79fe009e8aaf",
      #"a50c479446ee8df3c13dfec0b30d60cd1d5eea59af96f176434c8806c589fc323f7f89fe515ff6ea4bbba05d09b126f7",
    ]
  let cm =
    #"83d8c787f200ed00f65571df153b3e66a0d37ab654815e06226f4524ee36a7a0ac24043b75c089bd1b0752cfd56f2f9c"
  let h =
    #"978f48b9992d777719b15bbe88a1d91d8f13b9f8e8b508e2c1bb2aca2b7bd37b47c0f0dd913e7d8760e88d15658b016a"
  let hs =
    [
      #"a090cfe9261fdcfbe1b0b3f74256e57f6a5bdd98c13b0e09f9484838b02239a0ab8b883b7910585c13918f995eb8df89",
      #"865341b6a4affbe3b795d2d3c71781ad7267849fe2b24e728e13524d60d08e5a1681344b20268ea337d2fa2c1c3bbd7c",
      #"ae1dc44ad2d3084be3574e5feb59476b1c530322c1eab7d9a869372899cdfa75279ff5119ca6d2980e9e022a98a0ba6b",
      #"b358409e76fa35a23ec6f3e88bd963eb9da3ad83e59e3c005a3b4e050061fda1fe56227dcec8610061073795fb259b50",
      #"8bb97519cdb28bb8ceab19bb289c02856a542da4ce52fd3c2cbe8914986f7162a2632e94a6420e47c3d7503f2024fb3d",
      #"8d06e182789336765f00589a3dd16690ad368d656e95a4b7709bb7ba686d17ae7df5f23e91270bccf334632b3c86df99",
      #"994278e9661d267e2eaec3fee0a9302fc58347be0466778ea4ba55c9ca426a9856ef7479fc381e7408a9e01da5cc24de",
    ]
  let c =
    81255290470528926982282961061912418434326572650483297311183683195880829538006
  let to_challenge_issue_rs =
    to_challenge_issue(
      g1.decompress(cm),
      g1.decompress(h),
      g1.decompress(bw),
      list_bytearray_to_g1(hs),
      list_bytearray_to_g1(aw),
      list_bytearray_to_g1(cw),
    )
  expect c == from_bytearray_big_endian(to_challenge_issue_rs)
}

test hash_g1_test() {
  let g1_point =
    #"b979267a148f3329bb962656aef1fe9bc493c15783e0ecdfbcd0995211dd3914732a2c36fc27966de4a94b8c2f7a4d02"
  let g1_element = g1.decompress(g1_point)
  let hash = g1.compress(g1_element)
  expect hash == g1_point
}

pub fn to_challenge_open(
  h: G1Element,
  aw: G2Element,
  bw: G2Element,
  hs: List<G1Element>,
) -> ByteArray {
  let g1_bytes = g1_to_binary256(g1.generator)
  let g2_bytes = g2_to_binary256(g2.generator)
  let h_bytes = g1_to_binary256(h)
  let bw_bytes = g2_to_binary256(bw)
  let hs_bytes = list_g1_to_binary256(hs)
  let aw_bytes = g2_to_binary256(aw)
  let first_c = concat(g1_bytes, g2_bytes)
  let second_c = concat(first_c, h_bytes)
  let third_c = concat(second_c, aw_bytes)
  let fourth_c = concat(third_c, bw_bytes)
  let fifth_c = concat(fourth_c, hs_bytes)
  sha2_256(fifth_c)
}

test to_challenge_open_test() {
  let aw =
    #"8d17c4b14becb9136184fb35ac76cd631b16cd3c414eceb91f98268ef9a0f733b0f808896d9b36d38f495fcc3efbcb9d08fda23723a5913ea302a9ceb8477fe45e9a42a88027cde01b7d23a8f3c498a31e592ed6484421232aa538578889ec80"
  let bw =
    #"a71a4a4ca5a4018176b31585a58b80a9db86505d12ed9fee05f195b368ff8621f8121b930d7ff3a7b0b14364d766640814ff56234da1b74a022bf552862906084877aeed0185022f80da54d64898dd3741ace09b3ebaee76b6c010bb38a71d42"
  let h =
    #"8c1414d29dbffed035c0b0c6acf1719cb03eaf484a331f375737f72c3d68720ee7644ab73e2a55efd291198e32782e99"
  let hs =
    [
      #"a090cfe9261fdcfbe1b0b3f74256e57f6a5bdd98c13b0e09f9484838b02239a0ab8b883b7910585c13918f995eb8df89",
      #"865341b6a4affbe3b795d2d3c71781ad7267849fe2b24e728e13524d60d08e5a1681344b20268ea337d2fa2c1c3bbd7c",
      #"ae1dc44ad2d3084be3574e5feb59476b1c530322c1eab7d9a869372899cdfa75279ff5119ca6d2980e9e022a98a0ba6b",
      #"b358409e76fa35a23ec6f3e88bd963eb9da3ad83e59e3c005a3b4e050061fda1fe56227dcec8610061073795fb259b50",
      #"8bb97519cdb28bb8ceab19bb289c02856a542da4ce52fd3c2cbe8914986f7162a2632e94a6420e47c3d7503f2024fb3d",
      #"8d06e182789336765f00589a3dd16690ad368d656e95a4b7709bb7ba686d17ae7df5f23e91270bccf334632b3c86df99",
      #"994278e9661d267e2eaec3fee0a9302fc58347be0466778ea4ba55c9ca426a9856ef7479fc381e7408a9e01da5cc24de",
    ]
  let c =
    88026736549632845623902641450951592274924528375060517240887636654855702845898
  let to_challenge_open_rs =
    to_challenge_open(
      g1.decompress(h),
      g2.decompress(aw),
      g2.decompress(bw),
      list_bytearray_to_g1(hs),
    )
  expect c == from_bytearray_big_endian(to_challenge_open_rs)
}
