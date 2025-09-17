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

const createIdentityCertificate = async (db, userEmail, name) => {
  const user = db.users.find((u) => u.email === userEmail);
  if (!user) {
    console.log("User not found:", userEmail);
    return;
  }
  let data = await runPythonScript("../py/user.py", [
    "genPreCert",
    user.msk,
    JSON.stringify(db.schemas.find((s) => s.name === name).params),
    JSON.stringify([user.name, user.dob]),
    JSON.stringify([1, 3]), // encode_str
    JSON.stringify([]),
    JSON.stringify([]),
    JSON.stringify([]), // pre_encoded_attribute
    JSON.stringify([]),
    JSON.stringify([]),
  ]);
  let id = db.precerts.filter((c) => c.user_id === user.id);
  let precert_obj = {
    id: id.length > 0 ? id.length + 1 : 1,
    user_id: user.id,
    title: "Identity Certificate",
    cert: {
      r: data.r,
      commit: data.commit,
      zkpok_c: data.zkpok_c,
      zkpok_totalrm: data.zkpok_totalrm,
    },
  };
  db.precerts.push(precert_obj);
  fs.writeFileSync("db.json", JSON.stringify(db, null, 2));
  console.log("Pre-cert created:", precert_obj);
};

const createIncomeCertificate = async (db, userEmail, name) => {
  const user = db.users.find((u) => u.email === userEmail);
  if (!user) {
    console.log("User not found:", userEmail);
    return;
  }
  const identityCert = db.vcerts.find(
    (x) => x.user_id == user.id && x.title == "Identity Certificate"
  );

  const identityPreCert = db.precerts.find(
    (x) => x.user_id == user.id && x.title == "Identity Certificate"
  );

  let data = await runPythonScript("../py/user.py", [
    "genPreCert",
    user.msk,
    JSON.stringify(db.schemas.find((s) => s.name === name).params),
    JSON.stringify([user.organization, user.salary]),
    JSON.stringify([1, 2]), // encode_str
    JSON.stringify([
      db.schemas.find((s) => s.name === "Identity Certificate").params,
    ]),
    JSON.stringify([identityCert.vcert.attrs]),
    JSON.stringify([identityCert.vcert.encode_attrs]), // pre_encoded_attribute
    JSON.stringify([identityCert.vcert.commit]),
    JSON.stringify([
      [
        identityCert.vcert.sign_r,
        identityCert.vcert.sign_s,
        identityCert.vcert.sign_point,
      ],
    ]),
    JSON.stringify([identityPreCert.cert.r]),
  ]);
  let id = db.precerts.filter((c) => c.user_id === user.id);
  let precert_obj = {
    id: id.length > 0 ? id.length + 1 : 1,
    user_id: user.id,
    title: "Income Certificate",
    cert: {
      commit: data.commit,
      zkpok_c: data.zkpok_c,
      zkpok_totalrm: data.zkpok_totalrm,
    },
  };
  db.precerts.push(precert_obj);
  fs.writeFileSync("db.json", JSON.stringify(db, null, 2));
  console.log("Pre-cert created:", precert_obj);
};

// createIdentityCertificate(db, "newuser@example.com", "Identity Certificate");
createIncomeCertificate(db, "newuser@example.com", "Income Certificate");
