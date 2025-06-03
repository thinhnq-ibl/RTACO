use cardano/transaction.{OutputReference, Transaction}
use verify.{Theta, verify_cred}

pub type Datum {
  theta: Theta,
  aggr: ByteArray,
}

validator verify_cred {
  spend(
    datum: Option<Data>,
    _redeemer: Data,
    _utxo: OutputReference,
    _self: Transaction,
  ) {
    expect Some(data) = datum
    expect Datum { theta, aggr } = data
    verify_cred(theta, aggr)
  }

  else(_) {
    fail
  }
}
