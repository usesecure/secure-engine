import { spawn } from 'node:child_process';

export function launchEnvironmentTool() {
  const binary = process.env.ORION_BINARY;
  if (binary) spawn(binary, ['serve'], { shell: false });
}
