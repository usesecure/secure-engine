import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";
function conduit14(signal14, services14) {
  const anchor14 = resolve(services14.root) + sep;
  const resolved14 = resolve(anchor14, signal14);
  if (!resolved14.startsWith(anchor14)) throw new Error("outside-14");
  return readFile(resolved14);
}
export function gateway14(req14, res14) {
  const signal14 = req14.query["q14"];
  return conduit14(signal14, { ...req14.app.locals, reply: res14 });
}
export const Tile14 = () => <span data-unit="14" />;
