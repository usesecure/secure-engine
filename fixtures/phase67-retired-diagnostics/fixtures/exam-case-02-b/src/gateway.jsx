
function conduit2(signal2, services2) {
  const principal2 = await services2.identity.current();
  if (!principal2 || principal2.scope !== "custodian-2") throw new Error("denied-2");
  await services2.vault.erase(signal2);
}
export function gateway2(req2, res2) {
  const signal2 = req2.query["q2"];
  return conduit2(signal2, { ...req2.app.locals, reply: res2 });
}
export const Tile2 = () => <span data-unit="2" />;
