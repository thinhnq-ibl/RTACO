import { runPythonScript } from "./run_py.js";
import fs from "fs";

const data = fs.readFileSync("db.json");
const db = JSON.parse(data);

const createUser = async (db, user) => {
  if (db.users.find((u) => u.email === user.email)) {
    console.log("User already exists:", user.email);
    return;
  }
  let data = await runPythonScript("../py/user.py", ["genRandom"]);
  console.log("Generated msk:", data.msk);
  db.users.push({ ...user, msk: data.msk });
  fs.writeFileSync("db.json", JSON.stringify(db, null, 2));
  console.log("User created:", user);
};

// createUser(db, {
//   id: db.users.length + 1,
//   name: "Justin",
//   dob: "2000-01-01",
//   email: "newuser@example.com",
//   organization: "UCLA",
//   salary: 100000,
// });

const createIdentityCredential = async (db, userEmail, name) => {
  const user = db.users.find((u) => u.email === userEmail);
  if (!user) {
    console.log("User not found:", userEmail);
    return;
  }
  let data = await runPythonScript("../py/user.py", [
    "genPreCert",
    user.msk,
    db.schemas.find((s) => s.name === name).params,
    [user.name, user.dob],
    [1, 3], // encode_str
    [],
    [],
    [], // pre_encoded_attribute
  ]);
  let id = db.precert.filter((c) => c.userId === user.id);
  let precert_obj = {
    id: id.length > 0 ? id.length + 1 : 1,
    userId: user.id,
    title: "Identity Certificate",
    cert: {
      commit: data.commit,
      zkpok_c: data.zkpok_c,
      zkpok_totalrm: data.zkpok_totalrm,
    },
  };
  db.precert.push(precert_obj);
  fs.writeFileSync("db.json", JSON.stringify(db, null, 2));
  console.log("Pre-cert created:", precert_obj);
};

createIdentityCredential(db, "newuser@example.com", "Identity Certificate");
