import fs from "fs";

export function readThroughUnknownResolver(request: any, resolver: (value: string) => string) {
  return fs.readFile(resolver(request.query.document), () => undefined);
}
