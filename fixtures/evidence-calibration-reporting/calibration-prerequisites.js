import { readFile, rm, writeFile } from 'node:fs/promises';

export async function lowerPrivilegeIntegrityBoundary(request) {
  return writeFile(request.body.path, request.body.content);
}

export async function lowerPrivilegeAvailabilityBoundary(request) {
  return rm(request.query.path);
}

export async function lowerPrivilegeReadWithoutDisclosure(request) {
  return readFile(request.query.path);
}

export async function processEquivalentIntegrityBoundary(content) {
  return writeFile(process.env.RUNTIME_OUTPUT_PATH, content);
}

export async function constantPathControl(content) {
  return writeFile('/srv/neutral-store/fixed.txt', content);
}
