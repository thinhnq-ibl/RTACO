const { bls12_381 } = require("@noble/curves/bls12-381");
let bls = bls12_381;
const { randomBytes } = require("@noble/hashes/utils");

// Helper: Convert hex to bigint
const hexToBigInt = (hex) => BigInt(`0x${hex}`);

// // 1. Key Generation
// const privateKey = randomBytes(32); // Signer's private key
// const publicKey = bls.getPublicKey(privateKey); // Signer's public key
// console.log("Public Key:", publicKey.length);

// // 2. User: Blind a message
// const message = "Hello, BLS blind signatures!";
// const r =
//   hexToBigInt(Buffer.from(randomBytes(32)).toString("hex")) % bls.params.r; // Blinding factor
// const rG = bls.G1.ProjectivePoint.BASE.multiply(r); // r*G (blinding factor in G1)

// // Hash message to G2 (BLS signs in G2, verifies in G1)
// const messageBytes = new TextEncoder().encode(message);
// const hashedMsg = bls.G2.hashToCurve(messageBytes);
// console.log(bls.params.r);
// // Blinded message: H(m) + r*H(0) (for simplicity, we use r*G2)
// const rG2 = bls.G2.ProjectivePoint.BASE.multiply(r);
// const blindedMsg = rG2.add(rG2);

// // 3. Signer: Signs the blinded message (in G1)
// const blindSignature = bls.signShortSignature(
//   blindedMsg.toRawBytes(),
//   privateKey
// );

// console.log("Blind Signature:", blindSignature.length);

// // 4. User: Unblind the signature
// // Unblinding: σ_unblind = σ_blind - r*PK
// const rPK = bls.G1.ProjectivePoint.fromHex(publicKey).multiply(r);
// const unblindedSig =
//   bls.G1.ProjectivePoint.fromHex(blindSignature).subtract(rPK);

// // 5. Verification
// const isValid = bls.verifyShortSignature(unblindedSig, hashedMsg, publicKey);
// console.log("Unblinded Signature Valid?", isValid);

// =====================
// INVERTED BLS SCHEME:
// - Signatures: G2 (96 bytes)
// - Messages: G1 (48 bytes)
// - Public Keys: G2 (96 bytes)
// =====================

// 1. Key Generation
const privateKey = randomBytes(32); // Secure random scalar
const publicKey = bls.getPublicKey(privateKey); // Returns G2 point (96 bytes)
console.log("Public Key:", publicKey.length);

const publicKeyL = bls.getPublicKeyForShortSignatures(privateKey); // Returns G2 point (96 bytes)

// 2. User: Blind the Message (in G1)
const message = "Hello, Inverted BLS!";
const messageBytes = new TextEncoder().encode(message);
const hashedMsg = bls.G1.hashToCurve(messageBytes); // G1 point (48 bytes)

// Generate blinding factor (must be < curve order)
// const r = bls.CURVE.Fr.random();
const r =
  hexToBigInt(Buffer.from(randomBytes(32)).toString("hex")) % bls.params.r; // Blinding factor
const rG1 = bls.G1.ProjectivePoint.BASE.multiply(r); // r*G1
const blindedMsg = hashedMsg.add(rG1); // H(m) + r*G1 (G1 point)

// 3. Signer: Signs Blinded Message (returns G2 signature)
const blindSignature = bls.signShortSignature(
  blindedMsg.toRawBytes(),
  privateKey
); // 96 bytes

// 4. User: Unblind the Signature (in G2)
const rPK = bls.G1.ProjectivePoint.fromHex(publicKey).multiply(r); // r*PK (G2)
const unblindedSig =
  bls.G1.ProjectivePoint.fromHex(blindSignature).subtract(rPK);

// 5. Verification
const isValid = bls.verifyShortSignature(
  unblindedSig.toRawBytes(), // Unblinded G2 signature (96 bytes)
  bls.G1.ProjectivePoint.fromHex(hashedMsg.toRawBytes()), // Original G1 message (48 bytes)
  publicKeyL // G2 public key (96 bytes)
);

console.log("Inverted BLS Signature Valid?", isValid);
