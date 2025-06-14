use aiken/collection/list.{head, last}
use bls.{Sign}
use cardano/transaction.{OutputReference, Transaction}
use request.{G2Point, IssueProof, Vcert, check_vcerts}

pub type VcertData {
  commit: List<ByteArray>,
  r: Int,
  s: Int,
  r_g1: ByteArray,
}

pub type Datum {
  vcerts_data: List<VcertData>,
}

pub type Redeem {
  iproof: IssueProof,
}

validator verify_simple_vcert {
  spend(
    datum: Option<Data>,
    redeemer: Data,
    _utxo: OutputReference,
    _self: Transaction,
  ) {
    expect Some(data) = datum
    expect Datum { vcerts_data } = data
    expect Redeem { iproof } = redeemer
    let vcerts =
      list.map(
        vcerts_data,
        fn(n) {
          expect Some(x) = head(n.commit)
          expect Some(y) = last(n.commit)
          Vcert {
            commit: G2Point { x, y },
            signature: Sign { r: n.r, s: n.s, r_g1: n.r_g1 },
          }
        },
      )
    // check_vcerts(iproof, vcerts)
    True
  }

  else(_) {
    fail
  }
}
