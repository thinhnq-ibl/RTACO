const crypto = require("crypto");

// 🔹 Hash function (SHA-256)
function hash(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

// 🔹 Generate a random number in a range
function randomInRange(max) {
  return crypto.randomBytes(4).readUInt32BE(0) % max; // 4 bytes = 32-bit integer
}

// 🔹 User (Prover)
class User {
  constructor(name, dob) {
    this.salt = crypto.randomBytes(16).toString("hex"); // Random salt
    this.commitment = hash(`${name}${dob}${this.salt}`); // Store commitment on the server
  }

  // Step 1: Generate a random commitment R
  generateCommitment() {
    this.r = randomInRange(1000000);
    this.R = hash(`${this.commitment}${this.r}`); // Use commitment instead of name & DOB
    return this.R;
  }

  // Step 3: Generate a response to challenge c
  generateResponse(c) {
    this.s = this.r + c; // Simple additive relation
    return this.s;
  }
}

// 🔹 Server (Verifier)
class Server {
  constructor(commitment) {
    this.commitment = commitment;
  }

  // Step 2: Generate a random challenge c
  generateChallenge() {
    this.c = randomInRange(1000000);
    return this.c;
  }

  // Step 4: Verify the proof without using name & DOB
  verifyProof(R, s, c) {
    const reconstructedR = hash(`${this.commitment}${s - c}`);
    return R === reconstructedR;
  }
}

// 🔹 Example Usage
const name = "Alice";
const dob = "1990-01-01";

// 🔹 Step 1: User creates a commitment
const user = new User(name, dob);
const R = user.generateCommitment();
console.log("✅ Commitment generated:", R);

// 🔹 Step 2: Server generates a challenge
const server = new Server(user.commitment);
const c = server.generateChallenge();
console.log("✅ Challenge generated:", c);

// 🔹 Step 3: User generates a response
const s = user.generateResponse(c);
console.log("✅ Response generated:", s);

// 🔹 Step 4: Server verifies the proof
const isValid = server.verifyProof(R, s, c);
console.log("✅ Proof is valid:", isValid); // Should print true
