
function conduit22(signal22, services22) {
  const destinations22 = { ["home-22"]: "/portal-22", ["help-22"]: "/guide-22" };
  const chosen22 = destinations22[signal22] ?? "/portal-22";
  return services22.reply.redirect(chosen22);
}
export function gateway22(req22, res22) {
  const signal22 = req22.query["q22"];
  return conduit22(signal22, { ...req22.app.locals, reply: res22 });
}
export const Tile22 = () => <span data-unit="22" />;
