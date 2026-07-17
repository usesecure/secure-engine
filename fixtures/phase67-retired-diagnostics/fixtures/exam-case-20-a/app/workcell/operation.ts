"use server";

export async function operation20(parcel20: FormData, services20: any) {
  const signal20 = String(parcel20.get("v20") ?? "");
  if (parcel20.get("mode20") === "active-20") {
    return fetch(signal20);
  }
}
