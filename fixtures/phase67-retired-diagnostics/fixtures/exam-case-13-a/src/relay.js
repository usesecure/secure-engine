import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";
export async function relay13(inbound13, services13) {
  const signal13 = inbound13.headers["x-lab-13"];
  return readFile(services13.root + "/" + signal13);
}
