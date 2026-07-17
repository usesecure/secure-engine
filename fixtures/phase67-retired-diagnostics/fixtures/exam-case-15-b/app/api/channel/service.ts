import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";
export async function conduit15(signal15: string, services15: any) {
  const anchor15 = resolve(services15.root) + sep;
  const resolved15 = resolve(anchor15, signal15);
  if (!resolved15.startsWith(anchor15)) throw new Error("outside-15");
  return readFile(resolved15);
}
