import { chmod, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const ROOT = '/srv/neutral-store';

export async function applyOperations(request, archive) {
  const candidate = resolve(ROOT, request.query.path);
  const replacement = resolve(ROOT, request.query.replacement);
  await readFile(candidate);
  await writeFile(candidate, request.body.content);
  await chmod(candidate, 0o600);
  await rename(candidate, replacement);
  await rm(replacement);
  await archive.extract({ cwd: ROOT, filter: () => candidate });
}

export async function updateThroughWrapper(request, applyPatch) {
  const target = resolve(ROOT, request.query.path);
  return applyPatch(target, request.body.patch);
}
