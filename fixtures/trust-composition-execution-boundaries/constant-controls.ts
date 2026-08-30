import { workspace } from 'vscode';
import { spawn } from 'node:child_process';

export function launchConstantTool() {
  const userBinary = workspace.getConfiguration('orion').inspect<string>('binary')?.globalValue;
  const defaultBinary = workspace.getConfiguration('orion').inspect<string>('binary')?.defaultValue;
  spawn('/usr/bin/orion', ['serve'], {
    cwd: '/srv/orion',
    env: { ORION_MODE: 'safe' },
    shell: false,
  });
  void userBinary;
  void defaultBinary;
}
