import { spawn } from 'node:child_process';
import { readUserBinary, readWorkspaceBinary } from './helpers';

export function launchThroughHelper() {
  const controlled = readWorkspaceBinary();
  const user = readUserBinary();
  if (controlled) spawn(controlled, ['serve'], { shell: false });
  if (user) spawn('/usr/bin/orion', ['inspect', user], { shell: false });
}
