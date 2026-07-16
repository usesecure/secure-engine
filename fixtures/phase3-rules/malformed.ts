export function recovered(request: any) {
  const value = request.query.value;
  return value
// intentionally malformed so bounded recovery remains observable
