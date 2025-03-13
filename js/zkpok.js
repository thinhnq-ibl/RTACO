const crypto = require("crypto");
// Helper function to hash data using SHA-256
function hash(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}
// Helper function to generate a random number in a range
function randomInRange(max) {
  return crypto.randomBytes(32).readUInt32BE(0) % max;
}
// Simulate a user (prover) and server (verifier)
class User {
  constructor(name, dob) {
    this.name = name;
    this.dob = dob;
    this.salt = crypto.randomBytes(16).toString("hex"); // Random salt for commitment
    this.commitment = hash(`${name}${dob}${this.salt}`); // Commitment stored on the server
  }
  // Step 1: Generate a commitment (R)
  generateCommitment() {
    this.r = randomInRange(1000000); // Random nonce
    this.R = hash(`${this.name}${this.dob}${this.r}`);
    return this.R;
  }
  // Step 3: Generate a response (s) to the challenge (c)
  generateResponse(c) {
    const data = `${this.name}${this.dob}`;
    this.s = this.r + c * parseInt(hash(data), 16); // Simplified response calculation
    return this.s;
  }
}
class Server {
  constructor(commitment) {
    this.commitment = commitment; // Commitment stored on the server
  }
  // Step 2: Generate a random challenge (c)
  generateChallenge() {
    this.c = randomInRange(1000000); // Random challenge
    return this.c;
  }
  // Step 4: Verify the proof
  verifyProof(R, s, c) {
    const reconstructedR = hash(
      `${this.commitment}${s - c * parseInt(hash(this.commitment), 16)}`
    );
    return R === reconstructedR;
  }
}
// Example usage
const name = "Alice";
const dob = "1990-01-01";
// Step 1: User creates a commitment
const user = new User(name, dob);
const R = user.generateCommitment();
// Step 2: Server generates a challenge
const server = new Server(user.commitment);
const c = server.generateChallenge();
// Step 3: User generates a response
const s = user.generateResponse(c);
// Step 4: Server verifies the proof
const isValid = server.verifyProof(R, s, c);
console.log("Proof is valid:", isValid);
