import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";
export async function conduit15(signal15: string, services15: any) {
  return readFile(services15.root + "/" + signal15);
}
