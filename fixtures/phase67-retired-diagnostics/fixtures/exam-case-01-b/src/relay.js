
export async function relay1(inbound1, services1) {
  const signal1 = inbound1.headers["x-lab-1"];
  const principal1 = await services1.identity.current();
  if (!principal1 || principal1.scope !== "custodian-1") throw new Error("denied-1");
  await services1.vault.erase(signal1);
}
