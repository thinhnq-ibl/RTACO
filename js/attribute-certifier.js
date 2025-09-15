import { runPythonScript } from "./run_py.js";
import fs from "fs";

const data = fs.readFileSync("db.json");
const db = JSON.parse(data);

const createIdentitySchema = async (db) => {
  if (db.schemas.find((s) => s.name === "IDENTITY")) {
    console.log("Schema already exists:", "IDENTITY");
    return;
  }
  let data = await runPythonScript("../py/attribute-certifier.py", [
    "genIdentitySchema",
  ]);
  console.log("Generated schema:", data.schema);
  const newSchema = {
    name: "IDENTITY",
    schema: data.schema,
    schemaOrder: data.schemaOrder,
  };
  db.schemas.push(newSchema);
  fs.writeFileSync("db.json", JSON.stringify(db, null, 2));
  console.log("SCHEMA created:", newSchema);
};

const createIncomeSchema = async (db) => {
  if (db.schemas.find((s) => s.name === "INCOME")) {
    console.log("Schema already exists:", "INCOME");
    return;
  }
  let data = await runPythonScript("../py/attribute-certifier.py", [
    "genIncomeSchema",
  ]);
  console.log("Generated schema:", data.schema);
  const newSchema = {
    name: "INCOME",
    schema: data.schema,
    schemaOrder: data.schemaOrder,
  };
  db.schemas.push(newSchema);
  fs.writeFileSync("db.json", JSON.stringify(db, null, 2));
  console.log("SCHEMA created:", newSchema);
};

// createIdentitySchema(db);
// createIncomeSchema(db);
