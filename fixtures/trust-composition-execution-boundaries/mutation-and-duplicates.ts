import { workspace } from 'vscode';
import { spawn } from 'node:child_process';

declare function selectRuntimeBinary(): string;

export function runtimeMutationAbstains() {
  let binary = workspace.getConfiguration('orion').inspect<string>('binary')?.workspaceValue;
  binary = selectRuntimeBinary();
  if (binary) spawn(binary, ['serve'], { shell: false });
}

function duplicateReader() {
  return workspace.getConfiguration('orion').inspect<string>('binary')?.workspaceValue;
}

function duplicateReader() {
  return '/usr/bin/orion';
}

export function duplicateDispatchAbstains() {
  const binary = duplicateReader();
  if (binary) spawn(binary, ['serve'], { shell: false });
}
