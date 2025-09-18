import { runPythonScript } from "./run_py.js";
import fs from "fs";

const data = fs.readFileSync("db.json");
const db = JSON.parse(data);

const createValidator = async (db) => {
  let data = await runPythonScript("../py/validator.py", [
    "genValidator",
    JSON.stringify(2),
    JSON.stringify("Loan Credential"),
  ]);
  console.log("Generated msk:", data);
  //   db.users.push({ ...user, msk: data.msk });
  //   fs.writeFileSync("db.json", JSON.stringify(db, null, 2));
  //   console.log("User created:", user);
};

createValidator(db);
