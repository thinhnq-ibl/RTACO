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

const signCertificate = async (db, userEmail, requestId, title) => {
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
    (r) => r.id == requestId && r.userId == user.id && r.title == title
  );
  if (!precert) {
    console.log("Request not found or not approved:", requestId);
    return;
  }

  let data = await runPythonScript("../py/attribute-certifier.py", [
    "signAttributeCertificate",
    schema.sk,
    schema.params,
    [user.name, user.dob],
    [1, 3],
    precert.cert.commit,
    precert.cert.zkpok_c,
    precert.cert.zkpok_totalrm,
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
  db.certs.push(cert_obj);
  fs.writeFileSync("db.json", JSON.stringify(db, null, 2));
  console.log("Certificate signed:", cert_obj);
};

// createSchema(db, "Identity Certificate");
// createSchema(db, "Income Certificate");
signCertificate(db, "newuser@example.com", 1, "Identity Certificate");
