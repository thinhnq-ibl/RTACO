use bls.{G2PointByteArray}
use cardano/transaction.{OutputReference, Transaction}
use request.{IssueProof, OpenProof, Vcert, request_cred}
use verify.{Theta, verify_cred}

pub type OpenProof1 {
  // g2 point list
  dw: List<G2PointByteArray>,
  // // g2 point list
  ew: List<G2PointByteArray>,
  c: List<Int>,
}

pub type BlindSignDatum {
  iproof: IssueProof,
  open: OpenProof,
  // vcerts: List<Vcert>,
  cm_compressed: ByteArray,
  h_compressed: ByteArray,
  hs_compressed: List<ByteArray>,
  include_indexes: List<List<Int>>,
  cw: List<ByteArray>,
  commits_compressed: List<ByteArray>,
}

pub type VerifyCredDatum {
  theta: Theta,
  aggr: ByteArray,
  alpha: G2PointByteArray,
  aw: G2PointByteArray,
  beta: List<G2PointByteArray>,
  disclose_attr: List<Int>,
  timestamp: Int,
  hs: List<ByteArray>,
}

pub type Redeemer {
  BlindSign
  VerifyCred
}

// 44 for BlindSign, 45 for VerifyCred

validator iith {
  spend(
    datum: Option<Data>,
    redeemer: Redeemer,
    _utxo: OutputReference,
    _self: Transaction,
  ) {
    when redeemer is {
      BlindSign -> {
        expect Some(data) = datum
        expect BlindSignDatum {
          iproof,
          open,
          cm_compressed,
          h_compressed,
          hs_compressed,
          include_indexes,
          cw,
          commits_compressed,
        } = data
        True
      }
      //     request_cred(
      //       iproof,
      //       open,
      //       vcerts,
      //       cm_compressed,
      //       h_compressed,
      //       hs_compressed,
      //       include_indexes,
      //       cw,
      //       commits_compressed,
      //     )
      VerifyCred -> True
    }
    // when redeemer is {
    //   BlindSign -> {
    //   }
    //   VerifyCred -> {
    //     expect Some(data) = datum
    //     expect VerifyCredDatum {
    //       theta,
    //       aggr,
    //       alpha,
    //       aw,
    //       beta,
    //       disclose_attr,
    //       timestamp,
    //       hs,
    //     } = data
    //     verify_cred(theta, aggr, alpha, aw, beta, disclose_attr, timestamp, hs)
    //   }
    // }
  }

  else(_) {
    fail
  }
}
