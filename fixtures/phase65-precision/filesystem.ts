import fs from "fs";
import path from "path";

const DOCUMENT_ROOT = "/srv/manuals";

export function readTemplatePath(request: any) {
  return fs.readFile(`${DOCUMENT_ROOT}/${request.query.document}`, () => undefined);
}

function composeArchivePath(fragment: string) {
  return DOCUMENT_ROOT + "/archive/" + fragment;
}

export function readHelperPath(request: any) {
  return fs.readFile(composeArchivePath(request.params.fragment), () => undefined);
}

function confineDocument(fragment: string) {
  const candidate = path.resolve(DOCUMENT_ROOT, fragment);
  if (!candidate.startsWith(DOCUMENT_ROOT + path.sep)) {
    throw new Error("document path is outside the approved root");
  }
  return candidate;
}

export function readConfinedPath(request: any) {
  return fs.readFile(confineDocument(request.query.document), () => undefined);
}

export function readNearMissPath(request: any) {
  const candidate = path.resolve(DOCUMENT_ROOT, request.query.document);
  if (!candidate.startsWith(DOCUMENT_ROOT + path.sep)) {
    console.warn("candidate would leave the document root");
  }
  return fs.readFile(candidate, () => undefined);
}
