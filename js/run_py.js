import { PythonShell } from "python-shell";

PythonShell.run("../py/off-chain.py", { mode: "text" }).then((messages) => {
  if (messages) {
    console.log(messages[0]);
    result = JSON.parse(messages[0]);
  }
  console.log("finished");
});
