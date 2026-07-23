'use server';

export function cloneRepository(form: FormData) {
  const repository = String(form.get('repository') ?? '');
  return childProcess.spawn('git', ['clone', '--', repository], { shell: false });
}

export function copyRows(form: FormData, database: Database) {
  const owner = String(form.get('owner') ?? '');
  return database.query('SELECT * FROM events WHERE owner = ?', [owner]);
}

export async function installDefaults(form: FormData) {
  const settings = form.get('settings');
  Object.assign(Object.create(null), settings);
}
