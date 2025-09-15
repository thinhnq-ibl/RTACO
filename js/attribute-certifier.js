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

// createSchema(db, "Identity");
createSchema(db, "Income");
