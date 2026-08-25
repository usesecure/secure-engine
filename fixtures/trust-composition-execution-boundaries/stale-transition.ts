import { workspace } from 'vscode';
import { spawn } from 'node:child_process';

declare function refreshState(): Promise<void>;

export async function launchAfterTransition() {
  const binary = workspace.getConfiguration('orion').inspect<string>('binary')?.workspaceValue;
  if (!workspace.isTrusted) return;
  await refreshState();
  if (binary) spawn(binary, ['serve'], { shell: false });
}
