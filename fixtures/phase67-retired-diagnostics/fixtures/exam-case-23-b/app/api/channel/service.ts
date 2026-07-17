
export async function conduit23(signal23: string, services23: any) {
  const destinations23 = { ["home-23"]: "/portal-23", ["help-23"]: "/guide-23" };
  const chosen23 = destinations23[signal23] ?? "/portal-23";
  return services23.reply.redirect(chosen23);
}
