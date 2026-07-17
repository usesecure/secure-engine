
export async function conduit3(signal3: string, services3: any) {
  const principal3 = await services3.identity.current();
  if (!principal3 || principal3.scope !== "custodian-3") throw new Error("denied-3");
  await services3.vault.erase(signal3);
}
