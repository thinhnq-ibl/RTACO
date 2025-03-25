const crypto = require("crypto");
const fs = require("fs");

let _publicKey;
let _privateKey;

if (fs.existsSync("private2.pem")) {
  _publicKey = fs.readFileSync("public2.pem", "utf8");

  // Read encrypted private key
  _privateKey = crypto.createPrivateKey({
    key: fs.readFileSync("private2.pem", "utf8"),
    passphrase: "top-secret",
    format: "pem",
    type: "pkcs8",
  });
} else {
  // 1. Generate Key Pair (Issuer's Keys - RSA)
  let { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  fs.writeFileSync("public2.pem", publicKey);
  fs.writeFileSync("private2.pem", privateKey);

  _privateKey = privateKey;
  _publicKey = publicKey;
}

// 2. Create a Certificate (JSON)
const certificateData = {
  orgnazation: "Org A",
  income: "3000",
};

// 3. Convert to String & Sign
const certString = JSON.stringify(certificateData);
const signer = crypto.createSign("SHA256");
signer.update(certString);
const signature = signer.sign(_privateKey, "base64"); // Digital Signature

// 4. Final Verifiable Certificate
const verifiableCertificate = {
  ...certificateData,
  signature, // Attached signature
  publicKey: _publicKey, // Issuer's public key (in real cases, use a trusted registry)
};

console.log("Verifiable Certificate:", verifiableCertificate);

// 5. Verification Function
function verifyCertificate(cert, publicKeya) {
  const { signature, publicKey, ...data } = cert;
  if (publicKeya != publicKey) {
    console.log("Public key does not match with the issuer's public key");
    return false;
  }
  const dataString = JSON.stringify(data);
  const verifier = crypto.createVerify("SHA256");
  verifier.update(dataString);
  const isVerified = verifier.verify(publicKeya, signature, "base64");
  console.log("Certificate Data:", data);
  console.log("Is Signature Verified?", isVerified);
  return isVerified;
}

// 6. Test Verification
const isVerified = verifyCertificate(verifiableCertificate, _publicKey);
console.log("Is Verified?", isVerified ? "✅ Valid" : "❌ Invalid");
