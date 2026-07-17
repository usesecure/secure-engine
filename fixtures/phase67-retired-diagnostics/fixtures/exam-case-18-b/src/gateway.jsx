
function conduit18(signal18, services18) {
  const destination18 = new URL(signal18);
  if (destination18.protocol !== "https:" || destination18.hostname !== "api18.example.test") throw new Error("blocked-18");
  return fetch(destination18);
}
export function gateway18(req18, res18) {
  const signal18 = req18.query["q18"];
  return conduit18(signal18, { ...req18.app.locals, reply: res18 });
}
export const Tile18 = () => <span data-unit="18" />;
