import { lstat, open, readlink, realpath, stat } from 'node:fs/promises';

export async function classifyRuntimeObject(candidate) {
  const lexical = candidate;
  const canonical = await realpath(lexical);
  const entry = await lstat(lexical);
  const target = await stat(canonical);
  const link = entry.isSymbolicLink() ? await readlink(lexical) : undefined;
  const handle = await open(canonical, 'r');
  const opened = await handle.stat();
  return { lexical, canonical, entry, target, link, opened };
}

export function unresolvedPlatformKinds() {
  return [
    'regular-file',
    'symbolic-link',
    'hard-link',
    'nested-linked-directory',
    'replacement-race',
    'fifo-or-device',
    'windows-junction-or-reparse-point',
    'mount-boundary',
  ];
}
