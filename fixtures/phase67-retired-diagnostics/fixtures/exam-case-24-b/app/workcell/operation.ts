"use server";

export async function operation24(parcel24: FormData, services24: any) {
  const signal24 = String(parcel24.get("v24") ?? "");
  if (parcel24.get("mode24") === "active-24") {
    const destinations24 = { ["home-24"]: "/portal-24", ["help-24"]: "/guide-24" };
    const chosen24 = destinations24[signal24] ?? "/portal-24";
    return services24.reply.redirect(chosen24);
  }
}
