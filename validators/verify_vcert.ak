use cardano/transaction.{OutputReference, Transaction}
use rtaco.{IssueProof, Vcert, check_vcerts}

pub type Datum {
  iproof: IssueProof,
  vcerts: List<Vcert>,
}

validator verify_vcert {
  spend(
    datum: Option<Data>,
    _redeemer: Data,
    _utxo: OutputReference,
    _self: Transaction,
  ) {
    expect Some(data) = datum
    expect Some(Datum { iproof, vcerts }) = data
    check_vcerts(iproof, vcerts)
  }

  else(_) {
    fail
  }
}
