use cardano/transaction.{OutputReference, Transaction}
use request.{IssueProof, Vcert, check_vcerts}

pub type Datum {
  iproof: IssueProof,
  vcerts: List<Vcert>,
}

validator verify_simple_vcert {
  spend(
    datum: Option<Data>,
    _redeemer: Data,
    _utxo: OutputReference,
    _self: Transaction,
  ) {
    expect Some(data) = datum
    expect Datum { iproof, vcerts } = data
    check_vcerts(iproof, vcerts)
  }

  else(_) {
    fail
  }
}
