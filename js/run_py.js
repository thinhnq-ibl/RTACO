import { PythonShell } from "python-shell";

export const runPythonScript = async (
  path = "../py/off-chain.py",
  args = []
) => {
  const messages = await PythonShell.run(path, {
    mode: "text",
    args: args,
  });
  if (messages) {
    return JSON.parse(messages);
  }
  return null;
};
