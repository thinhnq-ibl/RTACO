import { PythonShell } from "python-shell";

export const runPythonScript = async () => {
  const messages = await PythonShell.run("../py/off-chain.py", {
    mode: "text",
  });
  if (messages) {
    return JSON.parse(messages);
  }
  return null;
};
