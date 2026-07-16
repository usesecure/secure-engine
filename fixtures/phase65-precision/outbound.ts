const APPROVED_HOSTS = new Set(["updates.example.test", "mirror.example.test"]);
const BLOCKED_HOSTS = new Set(["metadata.invalid"]);

export function requestDirectDestination(request: any) {
  return fetch(request.query.endpoint);
}

function forwardDestination(value: string) {
  return value;
}

export function requestHelperDestination(request: any) {
  return fetch(forwardDestination(request.params.endpoint));
}

function approvedEndpoint(value: string) {
  const parsed = new URL(value);
  if (parsed.protocol !== "https:" || !APPROVED_HOSTS.has(parsed.hostname)) {
    throw new Error("destination is outside the outbound policy");
  }
  return parsed;
}

export function requestApprovedDestination(request: any) {
  return fetch(approvedEndpoint(request.query.endpoint));
}

export function requestNearMissDestination(request: any) {
  const parsed = new URL(request.query.endpoint);
  if (parsed.protocol !== "https:" || !APPROVED_HOSTS.has(parsed.hostname)) {
    console.warn("destination would violate policy");
  }
  return fetch(parsed);
}

export function requestWithInvertedBlocklist(request: any) {
  const parsed = new URL(request.query.endpoint);
  if (parsed.protocol !== "https:" || !BLOCKED_HOSTS.has(parsed.hostname)) {
    throw new Error("only a blocked host would pass this inverted policy");
  }
  return fetch(parsed);
}
