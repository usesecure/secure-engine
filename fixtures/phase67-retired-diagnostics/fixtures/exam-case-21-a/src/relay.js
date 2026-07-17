
export async function relay21(inbound21, services21) {
  const signal21 = inbound21.headers["x-lab-21"];
  return services21.reply.redirect(signal21);
}
