import { workspace } from 'vscode';
import { spawn } from 'node:child_process';

export function launchTrustedWorkspaceTool() {
  const binary = workspace.getConfiguration('orion').inspect<string>('binary')?.workspaceValue;
  if (!workspace.isTrusted) return;
  if (binary) spawn(binary, ['serve'], { shell: false });
}
