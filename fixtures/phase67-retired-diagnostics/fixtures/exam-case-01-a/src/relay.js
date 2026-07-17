
export async function relay1(inbound1, services1) {
  const signal1 = inbound1.headers["x-lab-1"];
  await services1.vault.erase(signal1);
}
