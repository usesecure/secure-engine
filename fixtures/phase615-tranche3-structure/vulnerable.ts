'use server';

export function cloneRepository(form: FormData) {
  const repository = String(form.get('repository') ?? '');
  return childProcess.spawn('git', ['clone', repository], { shell: false });
}

export function copyRows(form: FormData, database: Database) {
  const option = String(form.get('option') ?? '');
  return database.query(`COPY events TO STDOUT WITH (${option})`);
}

export async function installDefaults(form: FormData) {
  const settings = form.get('settings');
  Object.assign(Object.prototype, settings);
}
