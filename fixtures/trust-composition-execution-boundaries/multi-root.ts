import { workspace } from 'vscode';
import { spawn } from 'node:child_process';

declare function isTrustedScope(resource: unknown): boolean;

export function launchEachFolder(folders: Array<{ uri: unknown }>) {
  for (const folder of folders) {
    const binary = workspace.getConfiguration('orion', folder.uri)
      .inspect<string>('binary')?.workspaceFolderValue;
    if (!isTrustedScope(folder.uri)) continue;
    if (binary) spawn(binary, ['serve'], { shell: false });
  }
}

export function launchWithWrongRoot(
  selected: { uri: unknown },
  checked: { uri: unknown },
) {
  const binary = workspace.getConfiguration('orion', selected.uri)
    .inspect<string>('binary')?.workspaceFolderValue;
  if (!isTrustedScope(checked.uri)) return;
  if (binary) spawn(binary, ['serve'], { shell: false });
}
