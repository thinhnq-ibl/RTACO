use aiken/collection/list
use cardano/transaction.{OutputReference, Transaction}
use request.{IssueProof, Vcert, check_vcerts}

pub type Datum {
  vcerts: List<Vcert>,
}

pub type Redeem {
  iproof: IssueProof,
}

validator verify_simple_vcert {
  spend(
    _datum: Option<Data>,
    _redeemer: Data,
    _utxo: OutputReference,
    _self: Transaction,
  ) {
    // expect Some(data) = datum
    // expect Datum { vcerts } = data
    // expect Redeem { iproof } = redeemer
    // expect 2 == list.length(vcerts)
    // check_vcerts(iproof, vcerts)
    True
  }

  else(_) {
    fail
  }
}
