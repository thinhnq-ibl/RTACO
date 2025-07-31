use aiken/collection/list
use bls.{Sign}
use cardano/transaction.{OutputReference, Transaction}
use request.{IssueProof, Vcert, check_vcerts}

pub type VcertData {
  commit: ByteArray,
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
          Vcert {
            commit: n.commit,
            signature: Sign { r: n.r, s: n.s, r_g1: n.r_g1 },
          }
        },
      )
    check_vcerts(iproof, vcerts)
  }

  else(_) {
    fail
  }
}
