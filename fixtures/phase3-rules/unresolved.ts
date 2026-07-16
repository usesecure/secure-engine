export async function unresolved(name: string, callback: (value: unknown) => void) {
  const module = await import(name);
  callback(module.default);
}
