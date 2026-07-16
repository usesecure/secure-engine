export function requestUnknownBuilder(request: any, builder: (value: string) => URL) {
  return fetch(builder(request.query.endpoint));
}
