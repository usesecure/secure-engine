
export async function relay17(inbound17, services17) {
  const signal17 = inbound17.headers["x-lab-17"];
  return fetch(signal17);
}
