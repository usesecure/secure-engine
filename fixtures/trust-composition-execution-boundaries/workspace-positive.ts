import { workspace } from 'vscode';
import { spawn } from 'node:child_process';

export function launchWorkspaceTool() {
  const binary = workspace.getConfiguration('orion').inspect<string>('binary')?.workspaceValue;
  if (binary) spawn(binary, ['serve'], { shell: false });
}
