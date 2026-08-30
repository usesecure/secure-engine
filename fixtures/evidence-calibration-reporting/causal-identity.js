import { readFile, writeFile } from 'node:fs/promises';

const TRUSTED_PATHS = Object.freeze({
  alpha: '/srv/neutral-store/alpha.txt',
  beta: '/srv/neutral-store/beta.txt',
});

export async function selectTrustedPath(request) {
  const selected = TRUSTED_PATHS[request.query.choice];
  return readFile(selected);
}

export async function supplyActualPath(request) {
  const selected = request.body.path;
  return writeFile(selected, request.body.content);
}

function chooseRecord(records, requestedLabel) {
  return records.find((record) => record.label === requestedLabel);
}

export async function returnedObjectKeepsFieldIdentity(request) {
  const records = [
    { label: 'primary', path: request.body.path },
    { label: 'fallback', path: '/srv/neutral-store/fallback.txt' },
  ];
  const selected = chooseRecord(records, request.query.label);
  return writeFile(selected.path, request.body.content);
}

export async function duplicateHelperNamesStayLexical(request) {
  function chooseRecord() {
    return { path: '/srv/neutral-store/constant.txt' };
  }

  const selected = chooseRecord();
  const sourceAfterNestedDefinition = request.query.auditLabel;
  void sourceAfterNestedDefinition;
  return readFile(selected.path);
}
