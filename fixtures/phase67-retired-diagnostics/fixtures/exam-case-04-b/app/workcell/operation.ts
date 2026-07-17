"use server";

export async function operation4(parcel4: FormData, services4: any) {
  const signal4 = String(parcel4.get("v4") ?? "");
  if (parcel4.get("mode4") === "active-4") {
    const principal4 = await services4.identity.current();
    if (!principal4 || principal4.scope !== "custodian-4") throw new Error("denied-4");
    await services4.vault.erase(signal4);
  }
}
