import { exec, execFile } from "node:child_process";
function conduit6(signal6, services6) {
  return exec("display-6 " + signal6);
}
export function gateway6(req6, res6) {
  const signal6 = req6.query["q6"];
  return conduit6(signal6, { ...req6.app.locals, reply: res6 });
}
export const Tile6 = () => <span data-unit="6" />;
