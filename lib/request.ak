use aiken/collection/list.{head, last, tail}
use aiken/crypto.{sha2_256}
use aiken/crypto/bls12_381/g1 as g1
use aiken/crypto/bls12_381/g2 as g2
use aiken/crypto/bls12_381/scalar
use aiken/option.{is_none}
use aiken/primitive/bytearray.{concat}
use aiken/primitive/int.{from_bytearray_big_endian}
use bls.{
  G1PointByteArray, G2PointByteArray, Sign, do_ecdsa_verify, g1_to_binary256,
  g2_to_binary256, list_bytearray_to_g1, list_compressed_to_g1,
  list_compressed_to_g2, list_g1_to_binary256,
}

pub type Vcert {
  // G2 point
  commit: G2PointByteArray,
  // Sign struct
  signature: Sign,
}

pub type IssueProof {
  c: Int,
  rr: Int,
  ros: List<Int>,
  total_rm: List<List<Int>>,
  pubkeys: List<G1PointByteArray>,
}

pub type OpenProof {
  // g2 point list
  dw: List<G2PointByteArray>,
  // g2 point list
  ew: List<G2PointByteArray>,
  c: List<Int>,
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
    expect Some(commit_h) = head(first_vcert_.commit)
    expect Some(commit_l) = last(first_vcert_.commit)
    let check_result =
      do_ecdsa_verify(
        first_pk_,
        first_vcert_.signature,
        concat(commit_h, commit_l),
      )
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
    [
      #"075320f826a216c87da892bfc8aaacd2a75f5ccdfa62b72de3491b0bf079201a2def1fc9f18234df324976fdaf267870",
      #"112bdf0ec3b461ae5bf50d9d0cde259cfdaa4789a6a7595dc3a37a76d6bc7c11d14cfb7528a60ea753bba5e501af4d5a",
    ]
  let commit2 =
    [
      #"03324843cb50de5ba1dc8202d2f122a079857340727e63ad1227c3c9068acbd6039d452a6cf8b49405bd895c528582f3",
      #"19de1c7c436db928c356fc685aa32832ade4583760476d176f366c0fd5b92d4b93256afd144d2f815abd721d497d2aee",
    ]
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
  cm_compressed: G1PointByteArray,
  h_compressed: G1PointByteArray,
  hs_compressed: List<G1PointByteArray>,
  commits_compressed: List<G1PointByteArray>,
  proof: IssueProof,
  include_indexes: List<List<Int>>,
  cw_bytes: List<G1PointByteArray>,
) {
  let rm = get_rm(proof.total_rm, include_indexes)
  let commits = list_bytearray_to_g1(commits_compressed)
  let hs = list_bytearray_to_g1(hs_compressed)
  let h = g1.decompress(h_compressed)
  let cm = g1.decompress(cm_compressed)
  let aw = calculate_Aw(commits, proof.c, proof.ros, h, rm)
  let bw = calculate_Bw(proof.c, proof.rr, rm, cm, hs)
  // let cw = calculate_Cw(proof.total_rm, commits, proof.c, hs)
  let cw = list_bytearray_to_g1(cw_bytes)
  proof.c == from_bytearray_big_endian(
    to_challenge_issue(cm, h, bw, hs, aw, cw),
  ) % scalar.field_prime
}

test check_issue_proof_test() {
  let cm_compressed =
    #"b3ff7f0d403bd9735aaaf54e14ab8409766572dd7343a04703e764fec9be90a082d7a5c2b92b9fca149412e982db8efd"
  let h_compressed =
    #"b8ed5b8f9dc605471fd4a9d373318d0a4b230722169aacdeda85a6ad0c0c3ebfe6fa58a16b062086368437cf8d45f185"
  let hs_compressed =
    [
      #"a090cfe9261fdcfbe1b0b3f74256e57f6a5bdd98c13b0e09f9484838b02239a0ab8b883b7910585c13918f995eb8df89",
      #"865341b6a4affbe3b795d2d3c71781ad7267849fe2b24e728e13524d60d08e5a1681344b20268ea337d2fa2c1c3bbd7c",
    ]
  let commits_compressed =
    [
      #"83a30f27817b9a06550b8d7f81b5594281f35259660f30c9ebf4b09a7a249c644ab2918432e90b0d0c2887f25f14aceb",
      #"b0b3013fd69e7d201c862e9e4e5308ba7d4d39a2a602c384660a0cfbddb09dc5c167a2d07ee02f8e73b9a996012b5992",
    ]
  let proof =
    IssueProof {
      c: 42535636952854378490874194418722333779152010990979182213475440387396116429547,
      rr: 40675462214123865742431951389911046237865684117786381568714250885257348136441,
      ros: [
        47925282862226222643927521835608820926632670018838597296086614014727602246558,
        21687859965734279473419411257190997575311278370788120793865541862802550871605,
      ],
      total_rm: [
        [
          50308106295266800020532960251996643677383528606831312922664123595083067330785,
          5095311348487787861645372845191969718727204196912877257125842030966424005608,
          24215618229245167673429987719866984434968409701328374910407976599467102132405,
          23117088388493107445729512963030794110283280127530426202939187508228779289686,
        ],
        [
          50308106295266800020532960251996643677383528606831312922664123595083067330785,
          40928904529511035926773476820862854867207669516607935231354640227867095612728,
          25499875010848260697670552620696378616666315278639900420553745755017069746308,
        ],
        [],
      ],
      pubkeys: [
        #"a97b2135da7799823236baea87402c5cc00e3a61c99e9abf7c2d9c0c29d1c50fd5753e3076c5e3da091c861199ee72b7",
        #"b51cc7408bc47ad537c29fef899a73b784de41c2063d5aac5248623f3db3dd4131e1cd9af902d49b28bc38819ffb48eb",
      ],
    }

  let include_indexes = [[0, 0, 1, 0], [0, 1, 0]]
  let cw =
    [
      #"8bf40d9b47562565fbe0bbbf2c12f0ea74da8be42010895d003c5f770cf757f18bbadd34e00e97dca0d9b2bf128738de",
      #"b33f8d0af6f8a5def6c26579645803e9d12cd4498ca4be50179566c5cdce4493fd36ee62b2016ad9ffb3b1e4f5ef5bef",
    ]
  check_issue_proof(
    cm_compressed,
    h_compressed,
    hs_compressed,
    commits_compressed,
    proof,
    include_indexes,
    cw,
  )
}

pub fn get_rm(
  total_rm: List<List<Int>>,
  include_indexes: List<List<Int>>,
) -> List<Int> {
  let first_include_indexes = head(include_indexes)
  if is_none(first_include_indexes) {
    []
  } else {
    expect Some(first_) = head(total_rm)
    expect Some(first_include_indexes_) = first_include_indexes
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
  cm_compressed: G1PointByteArray,
  h_compressed: G1PointByteArray,
  hs_compressed: List<G1PointByteArray>,
  include_indexes: List<List<Int>>,
  cw: List<G1PointByteArray>,
  commits_compressed: List<G1PointByteArray>,
) {
  let result1 = check_vcerts(proof, vcerts)
  let result2 =
    check_issue_proof(
      cm_compressed,
      h_compressed,
      hs_compressed,
      commits_compressed,
      proof,
      include_indexes,
      cw,
    )
  let result3 = check_open_proof(h_compressed, hs_compressed, open_proof)
  result1 && result2 && result3
}

test request_cred_test() {
  let proof =
    IssueProof {
      c: 42535636952854378490874194418722333779152010990979182213475440387396116429547,
      rr: 40675462214123865742431951389911046237865684117786381568714250885257348136441,
      ros: [
        47925282862226222643927521835608820926632670018838597296086614014727602246558,
        21687859965734279473419411257190997575311278370788120793865541862802550871605,
      ],
      total_rm: [
        [
          50308106295266800020532960251996643677383528606831312922664123595083067330785,
          5095311348487787861645372845191969718727204196912877257125842030966424005608,
          24215618229245167673429987719866984434968409701328374910407976599467102132405,
          23117088388493107445729512963030794110283280127530426202939187508228779289686,
        ],
        [
          50308106295266800020532960251996643677383528606831312922664123595083067330785,
          40928904529511035926773476820862854867207669516607935231354640227867095612728,
          25499875010848260697670552620696378616666315278639900420553745755017069746308,
        ],
        [],
      ],
      pubkeys: [
        #"a97b2135da7799823236baea87402c5cc00e3a61c99e9abf7c2d9c0c29d1c50fd5753e3076c5e3da091c861199ee72b7",
        #"b51cc7408bc47ad537c29fef899a73b784de41c2063d5aac5248623f3db3dd4131e1cd9af902d49b28bc38819ffb48eb",
      ],
    }
  let open_proof =
    OpenProof {
      dw: [
        [
          #"b7d202145af60c01a1294e20a824ec0ff5a8bb3c8960a0862714fdad6f1d72afeb38c2ef9ede0efa80f4bc530e361c05",
          #"12f07e97e697747ff1732948b6a9588f0502bc78d5ebcfbc0ccbd599f12fa73086711a758e32c29ed65671cc75a4b742",
        ],
        [
          #"b17404753763b1a7a2c8f3eda805c94e7e5726ca2d8850fcc64e7da63501f228ddbaba2646761505034b41133f106f00",
          #"192f783e17209bfbf58196e6a81edf05d5694ea016a559aa8c1ea70a7e6a31320037b88e8f19d125bcadf9120e214fc6",
        ],
        [
          #"a9b246d918b61b40990060eed918839eed12404dcd4e8fee55fde61aa5f7f532e6aa46fb89a8558c5997497c130ba1c9",
          #"13fb095a31ee0b02fb61b2e991027909810cd6140056cd47dc6ab5a8f8f9cdd48bf71683fe6315854992041cc5f32426",
        ],
      ],
      ew: [
        [
          #"b21b44aa690efa4366df2bab175f0f29dd58f3f05848199f1870b9a857a20cc0de9d862a9e773f6c0733b7582a8d3dec",
          #"0838b6c4c31121fc67a63f0a56f607cdbd9fbf6de1fbc81f89b2a0a2e967facc671c9e8bdf5341c5ab1b1b36e4a0618f",
        ],
        [
          #"a24e10a1f880d42e061513da1d224d009139b2aa1d52b7cc8b603c316a6a43f2d1a9862cf95cd59bf8aaf7e9fe5f0ccd",
          #"0d24adec785a3adea053b05e3c8a0369f5b95568b2ef8092e4aafaef6d4d5546f43e05133d0624956f9e6264e070b17c",
        ],
        [
          #"974932069a948e5776dd4d7928b26840a8188012ced6894a454552ddb6abf2b2dc946e56b8c493f7bec43fe5e69070f7",
          #"0a01382b44ed8653af6190c303009f2bf51f60eaa0f171fb3a24274515202d81baf143e4b17e276723a40574449af4e9",
        ],
      ],
      c: [
        13804325079850457725627142957951104827873126539730078258784195038440940880392,
        11726514466030405860930521000683610778958399959004350468181692188389284878278,
        51432526391402064059818130005060767434915237470275281612051755280949532972757,
      ],
    }
  let vcerts =
    [
      Vcert {
        commit: [
          #"075320f826a216c87da892bfc8aaacd2a75f5ccdfa62b72de3491b0bf079201a2def1fc9f18234df324976fdaf267870",
          #"112bdf0ec3b461ae5bf50d9d0cde259cfdaa4789a6a7595dc3a37a76d6bc7c11d14cfb7528a60ea753bba5e501af4d5a",
        ],
        signature: Sign {
          r: 1947564745249895947708144629914312558157305610980073189304752255321217468940983390413315295194393892376039785033790,
          s: 17355617863143591184525546256817223357573510192270296979117455415910592064385,
          r_g1: #"aca7513f4288ab39cdb45202f54678d9bd5d815b52295dc7f22b16c7572e13b93d96b6837288a909d801ce61a638f03e",
        },
      },
      Vcert {
        commit: [
          #"03324843cb50de5ba1dc8202d2f122a079857340727e63ad1227c3c9068acbd6039d452a6cf8b49405bd895c528582f3",
          #"19de1c7c436db928c356fc685aa32832ade4583760476d176f366c0fd5b92d4b93256afd144d2f815abd721d497d2aee",
        ],
        signature: Sign {
          r: 3924284939951961681834764047095286118299427666162894647982549458393534809915388538121180076697345644595416192308475,
          s: 30161833219843676097829195363654408677477538928028790969163359605163750361918,
          r_g1: #"b97f20c47b4d12e53f6cb898067b63532e53c906b200f2638db569a7d50977a7fbb53609e324b65a9934b3d08960d4fb",
        },
      },
    ]
  let cm_compressed =
    #"b3ff7f0d403bd9735aaaf54e14ab8409766572dd7343a04703e764fec9be90a082d7a5c2b92b9fca149412e982db8efd"
  let h_compressed =
    #"b8ed5b8f9dc605471fd4a9d373318d0a4b230722169aacdeda85a6ad0c0c3ebfe6fa58a16b062086368437cf8d45f185"
  let hs_compressed =
    [
      #"a090cfe9261fdcfbe1b0b3f74256e57f6a5bdd98c13b0e09f9484838b02239a0ab8b883b7910585c13918f995eb8df89",
      #"865341b6a4affbe3b795d2d3c71781ad7267849fe2b24e728e13524d60d08e5a1681344b20268ea337d2fa2c1c3bbd7c",
    ]
  let include_indexes = [[0, 0, 1, 0], [0, 1, 0]]
  let cw =
    [
      #"8bf40d9b47562565fbe0bbbf2c12f0ea74da8be42010895d003c5f770cf757f18bbadd34e00e97dca0d9b2bf128738de",
      #"b33f8d0af6f8a5def6c26579645803e9d12cd4498ca4be50179566c5cdce4493fd36ee62b2016ad9ffb3b1e4f5ef5bef",
    ]

  let commits =
    [
      #"83a30f27817b9a06550b8d7f81b5594281f35259660f30c9ebf4b09a7a249c644ab2918432e90b0d0c2887f25f14aceb",
      #"b0b3013fd69e7d201c862e9e4e5308ba7d4d39a2a602c384660a0cfbddb09dc5c167a2d07ee02f8e73b9a996012b5992",
    ]
  request_cred(
    proof,
    open_proof,
    vcerts,
    cm_compressed,
    h_compressed,
    hs_compressed,
    include_indexes,
    cw,
    commits,
  )
}

pub fn check_open_proof(
  h_compressed: G1PointByteArray,
  hs_compressed: List<G1PointByteArray>,
  proof: OpenProof,
) {
  let hs = list_compressed_to_g1(hs_compressed)
  let h = g1.decompress(h_compressed)
  let dw = list_compressed_to_g2(proof.dw)
  let ew = list_compressed_to_g2(proof.ew)
  check_open_challenge_item(h, hs, proof.c, dw, ew)
}

test check_open_proof_test() {
  let h_compressed =
    #"b8ed5b8f9dc605471fd4a9d373318d0a4b230722169aacdeda85a6ad0c0c3ebfe6fa58a16b062086368437cf8d45f185"
  // G1 point
  let hs_compressed =
    [
      #"a090cfe9261fdcfbe1b0b3f74256e57f6a5bdd98c13b0e09f9484838b02239a0ab8b883b7910585c13918f995eb8df89",
      #"865341b6a4affbe3b795d2d3c71781ad7267849fe2b24e728e13524d60d08e5a1681344b20268ea337d2fa2c1c3bbd7c",
    ]
  // G1 point
  let proof =
    OpenProof {
      c: [
        13804325079850457725627142957951104827873126539730078258784195038440940880392,
        11726514466030405860930521000683610778958399959004350468181692188389284878278,
        51432526391402064059818130005060767434915237470275281612051755280949532972757,
      ],
      dw: [
        [
          #"b7d202145af60c01a1294e20a824ec0ff5a8bb3c8960a0862714fdad6f1d72afeb38c2ef9ede0efa80f4bc530e361c05",
          #"12f07e97e697747ff1732948b6a9588f0502bc78d5ebcfbc0ccbd599f12fa73086711a758e32c29ed65671cc75a4b742",
        ],
        [
          #"b17404753763b1a7a2c8f3eda805c94e7e5726ca2d8850fcc64e7da63501f228ddbaba2646761505034b41133f106f00",
          #"192f783e17209bfbf58196e6a81edf05d5694ea016a559aa8c1ea70a7e6a31320037b88e8f19d125bcadf9120e214fc6",
        ],
        [
          #"a9b246d918b61b40990060eed918839eed12404dcd4e8fee55fde61aa5f7f532e6aa46fb89a8558c5997497c130ba1c9",
          #"13fb095a31ee0b02fb61b2e991027909810cd6140056cd47dc6ab5a8f8f9cdd48bf71683fe6315854992041cc5f32426",
        ],
      ],
      ew: [
        [
          #"b21b44aa690efa4366df2bab175f0f29dd58f3f05848199f1870b9a857a20cc0de9d862a9e773f6c0733b7582a8d3dec",
          #"0838b6c4c31121fc67a63f0a56f607cdbd9fbf6de1fbc81f89b2a0a2e967facc671c9e8bdf5341c5ab1b1b36e4a0618f",
        ],
        [
          #"a24e10a1f880d42e061513da1d224d009139b2aa1d52b7cc8b603c316a6a43f2d1a9862cf95cd59bf8aaf7e9fe5f0ccd",
          #"0d24adec785a3adea053b05e3c8a0369f5b95568b2ef8092e4aafaef6d4d5546f43e05133d0624956f9e6264e070b17c",
        ],
        [
          #"974932069a948e5776dd4d7928b26840a8188012ced6894a454552ddb6abf2b2dc946e56b8c493f7bec43fe5e69070f7",
          #"0a01382b44ed8653af6190c303009f2bf51f60eaa0f171fb3a24274515202d81baf143e4b17e276723a40574449af4e9",
        ],
      ],
    }
  check_open_proof(h_compressed, hs_compressed, proof)
}

pub fn check_open_challenge_item(
  h: G1Element,
  hs: List<G1Element>,
  c: List<Int>,
  dw: List<G2Element>,
  ew: List<G2Element>,
) -> Bool {
  let c_head = head(c)
  if is_none(c_head) {
    True
  } else {
    expect Some(c_) = c_head
    expect Some(dw_) = head(dw)
    expect Some(ew_) = head(ew)
    if c_ == from_bytearray_big_endian(to_challenge_open(h, dw_, ew_, hs)) {
      let tail_c_check = tail(c)
      if is_none(tail_c_check) {
        True
      } else {
        expect Some(tail_c) = tail(c)
        expect Some(tail_dw) = tail(dw)
        expect Some(tail_ew) = tail(ew)
        check_open_challenge_item(h, hs, tail_c, tail_dw, tail_ew)
      }
    } else {
      False
    }
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

test calculate_Aw_test() {
  let commitments =
    [
      g1.decompress(
        #"83a30f27817b9a06550b8d7f81b5594281f35259660f30c9ebf4b09a7a249c644ab2918432e90b0d0c2887f25f14aceb",
      ),
      g1.decompress(
        #"b0b3013fd69e7d201c862e9e4e5308ba7d4d39a2a602c384660a0cfbddb09dc5c167a2d07ee02f8e73b9a996012b5992",
      ),
    ]
  let c =
    42535636952854378490874194418722333779152010990979182213475440387396116429547
  let ros =
    [
      47925282862226222643927521835608820926632670018838597296086614014727602246558,
      21687859965734279473419411257190997575311278370788120793865541862802550871605,
    ]
  let h_point =
    g1.decompress(
      #"b8ed5b8f9dc605471fd4a9d373318d0a4b230722169aacdeda85a6ad0c0c3ebfe6fa58a16b062086368437cf8d45f185",
    )
  let rm =
    [
      24215618229245167673429987719866984434968409701328374910407976599467102132405,
      40928904529511035926773476820862854867207669516607935231354640227867095612728,
    ]
  let aw =
    [
      g1.decompress(
        #"ab7a8b4bd2be7fd951d0312b147ffd401b61c180cebea122ecbc24ccb1d5247c910be7015f6e1044ebb36c82fb897684",
      ),
      g1.decompress(
        #"95b6a550db44fc6ec638d72c28f1fc5686ea764a5c2ca374eb8bcefbbb7ff6b6707edfa435aa3d5b410041f7a651820c",
      ),
    ]
  let result = calculate_Aw(commitments, c, ros, h_point, rm)
  // trace result
  head(result) == head(aw) && tail(result) == tail(aw)
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

test calculate_Bw_test() {
  let c =
    42535636952854378490874194418722333779152010990979182213475440387396116429547
  let rr =
    40675462214123865742431951389911046237865684117786381568714250885257348136441
  let rm =
    [
      24215618229245167673429987719866984434968409701328374910407976599467102132405,
      40928904529511035926773476820862854867207669516607935231354640227867095612728,
    ]
  let cm_point =
    g1.decompress(
      #"b3ff7f0d403bd9735aaaf54e14ab8409766572dd7343a04703e764fec9be90a082d7a5c2b92b9fca149412e982db8efd",
    )
  let hs =
    [
      g1.decompress(
        #"a090cfe9261fdcfbe1b0b3f74256e57f6a5bdd98c13b0e09f9484838b02239a0ab8b883b7910585c13918f995eb8df89",
      ),
      g1.decompress(
        #"865341b6a4affbe3b795d2d3c71781ad7267849fe2b24e728e13524d60d08e5a1681344b20268ea337d2fa2c1c3bbd7c",
      ),
    ]
  let bw =
    g1.decompress(
      #"87c87c8e20b91ebe8ba0f69391936c732f50cc987028841e38ac77a3fc98a55c01f6edb73b42e7359a03b48834a68c92",
    )
  let result = calculate_Bw(c, rr, rm, cm_point, hs)
  // trace result
  result == bw
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

// todo
// test calculate_Cw_test() {
//   let total_rm =
//     [
//       [
//         50308106295266800020532960251996643677383528606831312922664123595083067330785,
//         5095311348487787861645372845191969718727204196912877257125842030966424005608,
//         24215618229245167673429987719866984434968409701328374910407976599467102132405,
//         23117088388493107445729512963030794110283280127530426202939187508228779289686,
//       ],
//       [
//         50308106295266800020532960251996643677383528606831312922664123595083067330785,
//         40928904529511035926773476820862854867207669516607935231354640227867095612728,
//         25499875010848260697670552620696378616666315278639900420553745755017069746308,
//       ],
//       [],
//     ]
//   let commits =
//     [
//       g1.decompress(
//         #"83a30f27817b9a06550b8d7f81b5594281f35259660f30c9ebf4b09a7a249c644ab2918432e90b0d0c2887f25f14aceb",
//       ),
//       g1.decompress(
//         #"b0b3013fd69e7d201c862e9e4e5308ba7d4d39a2a602c384660a0cfbddb09dc5c167a2d07ee02f8e73b9a996012b5992",
//       ),
//     ]
//   let c =
//     42535636952854378490874194418722333779152010990979182213475440387396116429547
//   let hs =
//     [
//       g1.decompress(
//         #"a090cfe9261fdcfbe1b0b3f74256e57f6a5bdd98c13b0e09f9484838b02239a0ab8b883b7910585c13918f995eb8df89",
//       ),
//       g1.decompress(
//         #"865341b6a4affbe3b795d2d3c71781ad7267849fe2b24e728e13524d60d08e5a1681344b20268ea337d2fa2c1c3bbd7c",
//       ),
//     ]
//   let cw =
//     [
//       g1.decompress(
//         #"8bf40d9b47562565fbe0bbbf2c12f0ea74da8be42010895d003c5f770cf757f18bbadd34e00e97dca0d9b2bf128738de",
//       ),
//       g1.decompress(
//         #"b33f8d0af6f8a5def6c26579645803e9d12cd4498ca4be50179566c5cdce4493fd36ee62b2016ad9ffb3b1e4f5ef5bef",
//       ),
//     ]
//   let result = calculate_Cw(total_rm, commits, c, hs)
//   // trace result
//   head(result) == head(cw) && tail(result) == tail(cw)
// }

pub fn calculate_Cw_item(
  total_rm: List<List<Int>>,
  commits: List<G1Element>,
  c: Int,
  hs: List<G1Element>,
) -> List<G1Element> {
  let commit_index = head(commits)
  if is_none(commit_index) {
    []
  } else {
    expect Some(first_) = head(total_rm)
    expect Some(commit_index_) = commit_index
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
  let first_hs = head(hs)
  if is_none(first_hs) {
    tmp
  } else {
    expect Some(first_) = head(total_rm_elemnt)
    expect Some(first_hs_) = first_hs
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

test to_challenge_issue_c_test() {
  let cm =
    g1.decompress(
      #"b3ff7f0d403bd9735aaaf54e14ab8409766572dd7343a04703e764fec9be90a082d7a5c2b92b9fca149412e982db8efd",
    )
  let h =
    g1.decompress(
      #"b8ed5b8f9dc605471fd4a9d373318d0a4b230722169aacdeda85a6ad0c0c3ebfe6fa58a16b062086368437cf8d45f185",
    )
  let bw =
    g1.decompress(
      #"87c87c8e20b91ebe8ba0f69391936c732f50cc987028841e38ac77a3fc98a55c01f6edb73b42e7359a03b48834a68c92",
    )
  let hs =
    list_compressed_to_g1(
      [
        #"a090cfe9261fdcfbe1b0b3f74256e57f6a5bdd98c13b0e09f9484838b02239a0ab8b883b7910585c13918f995eb8df89",
        #"865341b6a4affbe3b795d2d3c71781ad7267849fe2b24e728e13524d60d08e5a1681344b20268ea337d2fa2c1c3bbd7c",
      ],
    )
  let aw =
    list_compressed_to_g1(
      [
        #"ab7a8b4bd2be7fd951d0312b147ffd401b61c180cebea122ecbc24ccb1d5247c910be7015f6e1044ebb36c82fb897684",
        #"95b6a550db44fc6ec638d72c28f1fc5686ea764a5c2ca374eb8bcefbbb7ff6b6707edfa435aa3d5b410041f7a651820c",
      ],
    )
  let cw =
    list_compressed_to_g1(
      [
        #"8bf40d9b47562565fbe0bbbf2c12f0ea74da8be42010895d003c5f770cf757f18bbadd34e00e97dca0d9b2bf128738de",
        #"b33f8d0af6f8a5def6c26579645803e9d12cd4498ca4be50179566c5cdce4493fd36ee62b2016ad9ffb3b1e4f5ef5bef",
      ],
    )
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
  let hash = sha2_256(seventh_c)
  let c =
    42535636952854378490874194418722333779152010990979182213475440387396116429547
  c == from_bytearray_big_endian(hash) % scalar.field_prime
}

test to_challenge_issue_test() {
  let aw =
    [
      #"ab7a8b4bd2be7fd951d0312b147ffd401b61c180cebea122ecbc24ccb1d5247c910be7015f6e1044ebb36c82fb897684",
      #"95b6a550db44fc6ec638d72c28f1fc5686ea764a5c2ca374eb8bcefbbb7ff6b6707edfa435aa3d5b410041f7a651820c",
    ]
  let bw =
    #"87c87c8e20b91ebe8ba0f69391936c732f50cc987028841e38ac77a3fc98a55c01f6edb73b42e7359a03b48834a68c92"
  let cw =
    [
      #"8bf40d9b47562565fbe0bbbf2c12f0ea74da8be42010895d003c5f770cf757f18bbadd34e00e97dca0d9b2bf128738de",
      #"b33f8d0af6f8a5def6c26579645803e9d12cd4498ca4be50179566c5cdce4493fd36ee62b2016ad9ffb3b1e4f5ef5bef",
    ]
  let cm =
    #"b3ff7f0d403bd9735aaaf54e14ab8409766572dd7343a04703e764fec9be90a082d7a5c2b92b9fca149412e982db8efd"
  let h =
    #"b8ed5b8f9dc605471fd4a9d373318d0a4b230722169aacdeda85a6ad0c0c3ebfe6fa58a16b062086368437cf8d45f185"
  let hs =
    [
      #"a090cfe9261fdcfbe1b0b3f74256e57f6a5bdd98c13b0e09f9484838b02239a0ab8b883b7910585c13918f995eb8df89",
      #"865341b6a4affbe3b795d2d3c71781ad7267849fe2b24e728e13524d60d08e5a1681344b20268ea337d2fa2c1c3bbd7c",
    ]
  let c =
    42535636952854378490874194418722333779152010990979182213475440387396116429547
  let to_challenge_issue_rs =
    to_challenge_issue(
      g1.decompress(cm),
      g1.decompress(h),
      g1.decompress(bw),
      list_bytearray_to_g1(hs),
      list_bytearray_to_g1(aw),
      list_bytearray_to_g1(cw),
    )
  expect
    c == from_bytearray_big_endian(to_challenge_issue_rs) % scalar.field_prime
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
    #"b7d202145af60c01a1294e20a824ec0ff5a8bb3c8960a0862714fdad6f1d72afeb38c2ef9ede0efa80f4bc530e361c0512f07e97e697747ff1732948b6a9588f0502bc78d5ebcfbc0ccbd599f12fa73086711a758e32c29ed65671cc75a4b742"
  let bw =
    #"b21b44aa690efa4366df2bab175f0f29dd58f3f05848199f1870b9a857a20cc0de9d862a9e773f6c0733b7582a8d3dec0838b6c4c31121fc67a63f0a56f607cdbd9fbf6de1fbc81f89b2a0a2e967facc671c9e8bdf5341c5ab1b1b36e4a0618f"
  let h =
    #"b8ed5b8f9dc605471fd4a9d373318d0a4b230722169aacdeda85a6ad0c0c3ebfe6fa58a16b062086368437cf8d45f185"
  let hs =
    [
      #"a090cfe9261fdcfbe1b0b3f74256e57f6a5bdd98c13b0e09f9484838b02239a0ab8b883b7910585c13918f995eb8df89",
      #"865341b6a4affbe3b795d2d3c71781ad7267849fe2b24e728e13524d60d08e5a1681344b20268ea337d2fa2c1c3bbd7c",
    ]
  let c =
    13804325079850457725627142957951104827873126539730078258784195038440940880392
  let to_challenge_open_rs =
    to_challenge_open(
      g1.decompress(h),
      g2.decompress(aw),
      g2.decompress(bw),
      list_bytearray_to_g1(hs),
    )
  expect c == from_bytearray_big_endian(to_challenge_open_rs)
}

pub fn from_list_bytearray_to_G2_Point(g2_bytes: G2PointByteArray) -> G2Element {
  expect Some(g2_h) = head(g2_bytes)
  expect Some(g2_l) = last(g2_bytes)
  g2.decompress(concat(g2_h, g2_l))
}
