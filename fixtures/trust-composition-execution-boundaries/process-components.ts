import { workspace } from 'vscode';
import { exec, spawn } from 'node:child_process';

export function crossEveryBoundary() {
  const argv = workspace.getConfiguration('orion').inspect<string>('flag')?.workspaceValue;
  const envValue = workspace.getConfiguration('orion').inspect<string>('environment')?.workspaceValue;
  const cwd = workspace.getConfiguration('orion').inspect<string>('directory')?.workspaceValue;
  const shell = workspace.getConfiguration('orion').inspect<boolean>('shell')?.workspaceValue;
  const program = workspace.getConfiguration('orion').inspect<string>('program')?.workspaceValue;
  if (argv) spawn('/usr/bin/orion', [argv], { shell: false });
  if (envValue) spawn('/usr/bin/orion', ['serve'], { env: { ORION_MODE: envValue }, shell: false });
  if (cwd) spawn('/usr/bin/orion', ['serve'], { cwd, shell: false });
  if (shell !== undefined) spawn('/usr/bin/orion', ['serve'], { shell });
  if (program) exec(program);
}
