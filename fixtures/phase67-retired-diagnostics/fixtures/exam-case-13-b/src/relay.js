import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";
export async function relay13(inbound13, services13) {
  const signal13 = inbound13.headers["x-lab-13"];
  const anchor13 = resolve(services13.root) + sep;
  const resolved13 = resolve(anchor13, signal13);
  if (!resolved13.startsWith(anchor13)) throw new Error("outside-13");
  return readFile(resolved13);
}
