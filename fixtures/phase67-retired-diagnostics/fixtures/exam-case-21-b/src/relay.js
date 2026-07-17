
export async function relay21(inbound21, services21) {
  const signal21 = inbound21.headers["x-lab-21"];
  const destinations21 = { ["home-21"]: "/portal-21", ["help-21"]: "/guide-21" };
  const chosen21 = destinations21[signal21] ?? "/portal-21";
  return services21.reply.redirect(chosen21);
}
