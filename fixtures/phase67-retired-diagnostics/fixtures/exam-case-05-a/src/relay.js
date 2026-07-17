import { exec, execFile } from "node:child_process";
export async function relay5(inbound5, services5) {
  const signal5 = inbound5.headers["x-lab-5"];
  return exec("display-5 " + signal5);
}
