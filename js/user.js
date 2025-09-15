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

const createCommitZKP = async (db, title) => {
  let data = await runPythonScript("../py/user.py", ["genCommitZKP"]);
  console.log("Generated commitZKP:", data.commitZKP);
  db.commitZKPs.push({
    id: db.commitZKPs.length + 1,
    title,
    commitZKP: data.commitZKP,
  });
  fs.writeFileSync("db.json", JSON.stringify(db, null, 2));
  console.log("CommitZKP created:", { title, commitZKP: data.commitZKP });
};
