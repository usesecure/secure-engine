import { workspace } from 'vscode';

export function readWorkspaceBinary() {
  return workspace.getConfiguration('orion').inspect<string>('binary')?.workspaceValue;
}

export function readUserBinary() {
  return workspace.getConfiguration('orion').inspect<string>('binary')?.globalValue;
}
