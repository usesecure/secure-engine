"use server";
import { exec, execFile } from "node:child_process";
export async function operation8(parcel8: FormData, services8: any) {
  const signal8 = String(parcel8.get("v8") ?? "");
  if (parcel8.get("mode8") === "active-8") {
    return exec("display-8 " + signal8);
  }
}
