export function localOnly(value: string) {
  return value.trim();
}

app.get("/language-isolation", isolateLanguage);

function isolateLanguage(req: Request) {
  crossLanguage(req.body.command);
}
