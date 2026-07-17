import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";
function conduit14(signal14, services14) {
  return readFile(services14.root + "/" + signal14);
}
export function gateway14(req14, res14) {
  const signal14 = req14.query["q14"];
  return conduit14(signal14, { ...req14.app.locals, reply: res14 });
}
export const Tile14 = () => <span data-unit="14" />;
