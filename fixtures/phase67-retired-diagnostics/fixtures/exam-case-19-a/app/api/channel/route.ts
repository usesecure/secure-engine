import { conduit19 as transit19 } from "./service";
export async function GET(request19: Request) {
  const signal19 = /*SOURCE*/new URL(request19.url).searchParams.get("k19") ?? "";
  return transit19(signal19, globalThis.services19);
}
