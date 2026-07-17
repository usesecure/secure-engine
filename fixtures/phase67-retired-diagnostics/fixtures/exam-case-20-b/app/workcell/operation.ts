"use server";

export async function operation20(parcel20: FormData, services20: any) {
  const signal20 = String(parcel20.get("v20") ?? "");
  if (parcel20.get("mode20") === "active-20") {
    const destination20 = new URL(signal20);
    if (destination20.protocol !== "https:" || destination20.hostname !== "api20.example.test") throw new Error("blocked-20");
    return fetch(destination20);
  }
}
