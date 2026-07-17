"use server";

export async function operation28(parcel28: FormData, services28: any) {
  const signal28 = String(parcel28.get("v28") ?? "");
  if (parcel28.get("mode28") === "active-28") {
    return services28.database.query("SELECT label FROM catalog_28 WHERE code = '" + signal28 + "'");
  }
}
