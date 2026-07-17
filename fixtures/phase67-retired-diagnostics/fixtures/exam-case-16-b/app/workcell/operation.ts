"use server";
import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";
export async function operation16(parcel16: FormData, services16: any) {
  const signal16 = String(parcel16.get("v16") ?? "");
  if (parcel16.get("mode16") === "active-16") {
    const anchor16 = resolve(services16.root) + sep;
    const resolved16 = resolve(anchor16, signal16);
    if (!resolved16.startsWith(anchor16)) throw new Error("outside-16");
    return readFile(resolved16);
  }
}
