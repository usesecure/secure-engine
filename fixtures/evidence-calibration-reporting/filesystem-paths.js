import { open, readFile, realpath } from 'node:fs/promises';
import { relative, resolve, sep } from 'node:path';

const ROOT = '/srv/neutral-store';

function contained(root, candidate) {
  const offset = relative(root, candidate);
  return offset !== '..' && !offset.startsWith(`..${sep}`);
}

export async function lexicalContainment(request) {
  const candidate = resolve(ROOT, request.query.path);
  if (!contained(ROOT, candidate)) return;
  return readFile(candidate);
}

export async function separatorAwareLexicalContainment(request) {
  const candidate = resolve(ROOT, request.query.path);
  if (!candidate.startsWith(ROOT + sep)) throw new Error('outside root');
  return readFile(candidate);
}

export async function canonicalTarget(request) {
  const canonicalRoot = await realpath(ROOT);
  const candidate = await realpath(resolve(canonicalRoot, request.query.path));
  if (!contained(canonicalRoot, candidate)) return;
  return readFile(candidate);
}

export async function separatorAwareCanonicalTarget(request) {
  const base = await realpath(ROOT);
  const candidate = await realpath(resolve(base, request.query.path));
  if (!candidate.startsWith(base + sep)) throw new Error('outside root');
  return readFile(candidate);
}

export async function openedObjectWithoutRevalidation(request) {
  const candidate = resolve(ROOT, request.query.path);
  if (!contained(ROOT, candidate)) return;
  const handle = await open(candidate, 'r');
  return handle.readFile();
}

export async function sameHandleRevalidation(request) {
  const candidate = resolve(ROOT, request.query.path);
  if (!contained(ROOT, candidate)) return;
  const handle = await open(candidate, 'r');
  const before = await handle.stat();
  const content = await handle.readFile();
  const after = await handle.stat();
  if (before.dev !== after.dev || before.ino !== after.ino) return;
  return content;
}
