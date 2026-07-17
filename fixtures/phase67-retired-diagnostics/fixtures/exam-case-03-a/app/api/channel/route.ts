import { conduit3 as transit3 } from "./service";
export async function GET(request3: Request) {
  const signal3 = /*SOURCE*/new URL(request3.url).searchParams.get("k3") ?? "";
  return transit3(signal3, globalThis.services3);
}
