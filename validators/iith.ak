use cardano/transaction.{OutputReference, Transaction}
use request.{IssueProof, OpenProof, Vcert, request_cred}
use verify.{Theta, verify_cred}

pub type BlindSignDatum {
  iproof: IssueProof,
  open: OpenProof,
  vcerts: List<Vcert>,
  cm_compressed: ByteArray,
  h_compressed: ByteArray,
  hs_compressed: List<ByteArray>,
  include_indexes: List<List<Int>>,
  combine_hs_compressed: List<List<ByteArray>>,
  commits_compressed: List<ByteArray>,
  combine_commits_compressed: List<ByteArray>,
}

pub type VerifyCredDatum {
  theta: Theta,
  aggr: ByteArray,
  alpha: List<ByteArray>,
  aw: List<ByteArray>,
  beta: List<List<ByteArray>>,
  disclose_attr: List<Int>,
  timestamp: Int,
  hs_compressed: List<ByteArray>,
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
          vcerts,
          cm_compressed,
          h_compressed,
          hs_compressed,
          include_indexes,
          combine_hs_compressed,
          commits_compressed,
          combine_commits_compressed,
        } = data
        request_cred(
          iproof,
          open,
          vcerts,
          cm_compressed,
          h_compressed,
          hs_compressed,
          include_indexes,
          combine_hs_compressed,
          commits_compressed,
          combine_commits_compressed,
        )
      }
      VerifyCred -> {
        expect Some(data) = datum
        expect VerifyCredDatum {
          theta,
          aggr,
          alpha,
          aw,
          beta,
          disclose_attr,
          timestamp,
          hs_compressed,
        } = data
        verify_cred(
          theta,
          aggr,
          alpha,
          aw,
          beta,
          disclose_attr,
          timestamp,
          hs_compressed,
        )
      }
    }
  }

  else(_) {
    fail
  }
}
