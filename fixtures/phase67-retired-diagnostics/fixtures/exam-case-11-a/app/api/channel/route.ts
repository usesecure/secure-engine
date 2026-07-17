import { conduit11 as transit11 } from "./service";
export async function GET(request11: Request) {
  const signal11 = /*SOURCE*/new URL(request11.url).searchParams.get("k11") ?? "";
  return transit11(signal11, globalThis.services11);
}
