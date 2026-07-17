import { conduit15 as transit15 } from "./service";
export async function GET(request15: Request) {
  const signal15 = /*SOURCE*/new URL(request15.url).searchParams.get("k15") ?? "";
  return transit15(signal15, globalThis.services15);
}
