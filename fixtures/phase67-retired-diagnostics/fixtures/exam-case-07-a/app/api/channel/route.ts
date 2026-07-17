import { conduit7 as transit7 } from "./service";
export async function GET(request7: Request) {
  const signal7 = /*SOURCE*/new URL(request7.url).searchParams.get("k7") ?? "";
  return transit7(signal7, globalThis.services7);
}
