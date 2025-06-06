use cardano/transaction.{OutputReference, Transaction}
use verify.{Theta, verify_cred}

pub type Datum {
  theta: Theta,
  aggr: ByteArray,
  alpha: ByteArray,
  aw: ByteArray,
  beta: List<ByteArray>,
  disclose_attr: List<Int>,
  timestamp: Int,
  hs: List<ByteArray>,
}

validator verify_cred {
  spend(
    datum: Option<Data>,
    _redeemer: Data,
    _utxo: OutputReference,
    _self: Transaction,
  ) {
    expect Some(data) = datum
    expect Datum { theta, aggr, alpha, aw, beta, disclose_attr, timestamp, hs } =
      data
    verify_cred(theta, aggr, alpha, aw, beta, disclose_attr, timestamp, hs)
  }

  else(_) {
    fail
  }
}
