import { exec, spawn } from "child_process";

export function runTemplateCommand(request: any) {
  return exec(`status-tool --record ${request.query.record}`);
}

function assembleStatusCommand(record: string) {
  return "status-tool --record " + record;
}

export function runHelperCommand(request: any) {
  return exec(assembleStatusCommand(request.params.record));
}

export function runFixedExecutable(request: any) {
  return spawn("/usr/bin/status-tool", ["--record", request.query.record], { shell: false });
}

export function runNearMissCommand(request: any) {
  if (!/^[a-z0-9-]+$/i.test(request.query.record)) {
    console.warn("unexpected record syntax");
  }
  return exec("status-tool --record " + request.query.record);
}
