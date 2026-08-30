import { workspace } from 'vscode';
import { spawn } from 'node:child_process';

declare function isTrustedScope(resource: unknown): boolean;
declare const unrelatedResource: unknown;

export function launchFolderTool(folder: { uri: unknown }) {
  const binary = workspace.getConfiguration('orion', folder.uri)
    .inspect<string>('binary')?.workspaceFolderValue;
  if (!isTrustedScope(unrelatedResource)) return;
  if (binary) spawn(binary, ['serve'], { shell: false });
}
