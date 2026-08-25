import { workspace } from 'vscode';
import { spawn } from 'node:child_process';

declare function isTrustedScope(resource: unknown): boolean;

export function launchTrustedFolderTool(folder: { uri: unknown }) {
  const binary = workspace.getConfiguration('orion', folder.uri)
    .inspect<string>('binary')?.workspaceFolderValue;
  if (!isTrustedScope(folder.uri)) return;
  if (binary) spawn(binary, ['serve'], { shell: false });
}
