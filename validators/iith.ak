use aiken/collection/list
use bls.{list_compressed_to_g1, to_g1}
use cardano/assets.{PolicyId}
use cardano/transaction.{InlineDatum, OutputReference, Transaction}
use request.{IssueProof, OpenProof, Vcert, pubkey_contains, request_cred}
use verify.{Proof, Theta, verify_cred}

pub type CADatum {
  pubkeys: List<ByteArray>,
}

pub type BlindSignDatum {
  iproof: IssueProof,
  open: OpenProof,
  vcerts: List<Vcert>,
  cm_compressed: ByteArray,
  hs_compressed: List<ByteArray>,
  include_indexes: List<List<Int>>,
  combine_hs_compressed: List<List<ByteArray>>,
  commits_compressed: List<ByteArray>,
  combine_commits_compressed: List<ByteArray>,
}

pub type VerifyCredDatum {
  theta: Theta,
  aggr: List<ByteArray>,
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

pub type ThetaRedeemer {
  kappa: List<ByteArray>,
  nu: ByteArray,
  sigma: List<ByteArray>,
  proof: Proof,
}

pub type MintRedeemer {
  ReqCredentialMint
  BlindSignMint
  VerifyCredMint {
    theta: ThetaRedeemer,
    aggr: List<ByteArray>,
    alpha: List<ByteArray>,
    aw: List<ByteArray>,
    beta: List<List<ByteArray>>,
    disclose_attr: List<Int>,
    timestamp: Int,
    hs_compressed: List<ByteArray>,
  }
}

validator iith {
  mint(rdmr: MintRedeemer, policy_id: PolicyId, transaction: Transaction) {
    when rdmr is {
      ReqCredentialMint -> {
        let Transaction { inputs, reference_inputs, outputs, .. } = transaction
        expect Some(main_output) = list.head(outputs)
        expect InlineDatum(data) = main_output.datum
        expect BlindSignDatum { iproof, .. } = data
        expect Some(input_ref) = list.head(reference_inputs)
        expect InlineDatum(datum) = input_ref.output.datum
        expect CADatum { pubkeys } = datum
        pubkey_contains(iproof.pubkeys, pubkeys)
      }
      BlindSignMint -> {
        let Transaction { inputs, reference_inputs, outputs, .. } = transaction
        expect Some(input_ref) = list.head(reference_inputs)
        expect InlineDatum(datum) = input_ref.output.datum
        expect BlindSignDatum {
          iproof,
          open,
          vcerts,
          cm_compressed,
          hs_compressed,
          include_indexes,
          combine_hs_compressed,
          commits_compressed,
          combine_commits_compressed,
        } = datum
        request_cred(
          iproof,
          open,
          vcerts,
          cm_compressed,
          hs_compressed,
          include_indexes,
          combine_hs_compressed,
          commits_compressed,
          combine_commits_compressed,
        )
      }
      VerifyCredMint {
        theta,
        aggr,
        alpha,
        aw,
        beta,
        disclose_attr,
        timestamp,
        hs_compressed,
      } -> {
        let theta_datum =
          Theta {
            kappa: theta.kappa,
            nu: to_g1(theta.nu),
            sigma: list_compressed_to_g1(theta.sigma),
            proof: theta.proof,
          }
        verify_cred(
          theta_datum,
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

  spend(
    datum: Option<Data>,
    redeemer: Redeemer,
    _utxo: OutputReference,
    self: Transaction,
  ) {
    when redeemer is {
      BlindSign -> {
        expect Some(data) = datum
        expect BlindSignDatum {
          iproof,
          open,
          vcerts,
          cm_compressed,
          hs_compressed,
          include_indexes,
          combine_hs_compressed,
          commits_compressed,
          combine_commits_compressed,
        } = data
        expect Some(input_ref) = list.head(self.reference_inputs)
        expect InlineDatum(datum) = input_ref.output.datum
        expect CADatum { pubkeys } = datum
        expect pubkey_contains(iproof.pubkeys, pubkeys)
        request_cred(
          iproof,
          open,
          vcerts,
          cm_compressed,
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
