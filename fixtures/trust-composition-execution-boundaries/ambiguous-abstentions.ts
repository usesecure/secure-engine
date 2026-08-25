import { workspace } from 'vscode';
import { spawn } from 'node:child_process';

declare const decisionCache: Map<string, boolean>;
declare function choose(callback: () => void): void;

export function unresolvedEffectiveConfiguration() {
  const binary = workspace.getConfiguration('orion').get<string>('binary');
  if (binary) spawn(binary, ['serve'], { shell: false });
}

export function unresolvedCallbackLifecycle() {
  const binary = workspace.getConfiguration('orion').inspect<string>('binary')?.workspaceValue;
  choose(() => {
    if (binary) spawn(binary, ['serve'], { shell: false });
  });
}

export function unresolvedDecisionCache() {
  const binary = workspace.getConfiguration('orion').inspect<string>('binary')?.workspaceValue;
  if (decisionCache.get('orion')) return;
  if (binary) spawn(binary, ['serve'], { shell: false });
}
