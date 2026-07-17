"use server";
import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";
export async function operation16(parcel16: FormData, services16: any) {
  const signal16 = String(parcel16.get("v16") ?? "");
  if (parcel16.get("mode16") === "active-16") {
    return readFile(services16.root + "/" + signal16);
  }
}
