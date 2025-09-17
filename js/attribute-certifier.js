import { runPythonScript } from "./run_py.js";
import fs from "fs";

const data = fs.readFileSync("db.json");
const db = JSON.parse(data);

const createSchema = async (db, name) => {
  if (db.schemas.find((s) => s.name === name)) {
    console.log("Schema already exists:", name);
    return;
  }
  let data = await runPythonScript("../py/attribute-certifier.py", [
    `gen${name}Schema`,
  ]);
  console.log("Generated schema:", data.schema);
  const newSchema = {
    name: data.name,
    schema: data.schema,
    schemaOrder: data.schemaOrder,
    params: data.params,
    pk: data.pk,
    sk: data.sk,
  };
  db.schemas.push(newSchema);
  fs.writeFileSync("db.json", JSON.stringify(db, null, 2));
  console.log("SCHEMA created:", newSchema);
};

const signIdentityCertificate = async (db, userEmail, requestId, title) => {
  const user = db.users.find((u) => u.email === userEmail);
  if (!user) {
    console.log("User not found:", userEmail);
    return;
  }

  const schema = db.schemas.find((s) => s.name === title);
  if (!schema) {
    console.log("Schema not found:", title);
    return;
  }

  const precert = db.precerts.find(
    (r) => r.id == requestId && r.user_id == user.id && r.title == title
  );
  if (!precert) {
    console.log("Request not found or not approved:", requestId);
    return;
  }

  let data = await runPythonScript("../py/attribute-certifier.py", [
    "signAttributeCertificate",
    schema.sk,
    JSON.stringify(db.schemas.find((s) => s.name === title).params),
    JSON.stringify([user.name, user.dob]),
    JSON.stringify([1, 3]), // encode_str
    JSON.stringify(precert.cert.commit),
    JSON.stringify(precert.cert.zkpok_c),
    JSON.stringify(precert.cert.zkpok_totalrm),
    JSON.stringify([]),
    JSON.stringify([]),
    JSON.stringify([]),
  ]);
  console.log("Signed certificate data:", data);

  let cert_obj = {
    user_id: user.id,
    requestId: requestId,
    title: title,
    vcert: {
      attrs: [user.name, user.dob],
      encode_attrs: [1, 3],
      commit: precert.cert.commit,
      sign_r: data.vcert_r,
      sign_s: data.vcert_s,
      sign_point: data.vcert_p1,
    },
  };
  // db.vcerts.push(cert_obj);
  // fs.writeFileSync("db.json", JSON.stringify(db, null, 2));
  console.log("Certificate signed:", cert_obj);
};

const signIncomeCertificate = async (db, userEmail, requestId, title) => {
  const user = db.users.find((u) => u.email === userEmail);
  if (!user) {
    console.log("User not found:", userEmail);
    return;
  }

  const schema = db.schemas.find((s) => s.name === title);
  if (!schema) {
    console.log("Schema not found:", title);
    return;
  }

  const precert = db.precerts.find(
    (r) => r.id == requestId && r.user_id == user.id && r.title == title
  );
  if (!precert) {
    console.log("Request not found or not approved:", requestId);
    return;
  }

  const identityCert = db.vcerts.find(
    (r) => r.user_id == user.id && r.title == "Identity Certificate"
  );
  if (!identityCert) {
    console.log("Request not found or not approved:", requestId);
    return;
  }

  let data = await runPythonScript("../py/attribute-certifier.py", [
    "signAttributeCertificate",
    schema.sk,
    JSON.stringify(db.schemas.find((s) => s.name === title).params),
    JSON.stringify([user.organization, user.salary]),
    JSON.stringify([1, 2]), // encode_str
    JSON.stringify(precert.cert.commit),
    JSON.stringify(precert.cert.zkpok_c),
    JSON.stringify(precert.cert.zkpok_totalrm),
    JSON.stringify([
      db.schemas.find((s) => s.name === "Identity Certificate").params,
    ]),
    JSON.stringify([identityCert.vcert.commit]),
    JSON.stringify([
      [
        identityCert.vcert.sign_r,
        identityCert.vcert.sign_s,
        identityCert.vcert.sign_point,
      ],
    ]),
  ]);
  console.log("Signed certificate data:", data);

  let cert_obj = {
    user_id: user.id,
    requestId: requestId,
    title: title,
    vcert: {
      attrs: [user.organization, user.salary],
      encode_attrs: [1, 2],
      commit: precert.cert.commit,
      sign_r: data.vcert_r,
      sign_s: data.vcert_s,
      sign_point: data.vcert_p1,
    },
  };
  // db.vcerts.push(cert_obj);
  // fs.writeFileSync("db.json", JSON.stringify(db, null, 2));
  console.log("Certificate signed:", cert_obj);
};

// createSchema(db, "Identity Certificate");
// createSchema(db, "Income Certificate");
signIdentityCertificate(db, "newuser@example.com", 1, "Identity Certificate");
// signIncomeCertificate(db, "newuser@example.com", 2, "Income Certificate");
