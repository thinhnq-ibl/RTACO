import { PythonShell } from "python-shell";

PythonShell.run("../py/off-chain.py", null).then((messages) => {
  if (messages) console.log(messages);
  console.log("finished");
});
