import { conduit23 as transit23 } from "./service";
export async function GET(request23: Request) {
  const signal23 = /*SOURCE*/new URL(request23.url).searchParams.get("k23") ?? "";
  return transit23(signal23, globalThis.services23);
}
