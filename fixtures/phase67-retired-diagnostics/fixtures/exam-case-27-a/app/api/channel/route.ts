import { conduit27 as transit27 } from "./service";
export async function GET(request27: Request) {
  const signal27 = /*SOURCE*/new URL(request27.url).searchParams.get("k27") ?? "";
  return transit27(signal27, globalThis.services27);
}
