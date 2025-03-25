const { bls12_381 } = require("@noble/curves/bls12-381");
const bls = bls12_381;
async function blsAggregate() {
  // Generate keys
  const priv1 = bls.utils.randomPrivateKey();
  const priv2 = bls.utils.randomPrivateKey();
  const pub1 = bls.getPublicKey(priv1);
  const pub2 = bls.getPublicKey(priv2);

  // Sign messages
  const msg1 = new TextEncoder().encode("message1");
  // const msg2 = new TextEncoder().encode("message2");
  const sig1 = bls.sign(msg1, priv1);
  const sig2 = bls.sign(msg1, priv2);

  // Aggregate signatures
  const aggregated = bls.aggregateSignatures([sig1, sig2]);
  const aggregatedPubs = bls.aggregatePublicKeys([pub1, pub2]);

  // Verify
  // const messages = [msg1, msg2];
  const valid = bls.verify(aggregated, msg1, aggregatedPubs);
  console.log("Aggregate verification:", valid);
}

blsAggregate();
