import { redirect } from "next/navigation";

const APPROVED_REDIRECTS = new Set(["/account", "/receipts", "/support"]);
const REJECTED_REDIRECTS = new Set(["/legacy-external"]);

export function redirectDirectly(request: any) {
  return redirect(request.query.destination);
}

function passthroughDestination(value: string) {
  return value;
}

export function redirectThroughHelper(request: any) {
  return redirect(passthroughDestination(request.params.destination));
}

function selectApprovedDestination(nextDestination: string) {
  if (!APPROVED_REDIRECTS.has(nextDestination)) {
    return "/account";
  }
  return nextDestination;
}

export function redirectToApprovedDestination(request: any) {
  return redirect(selectApprovedDestination(request.query.destination));
}

export function redirectWithSafeFallback(request: any) {
  const nextDestination = request.query.destination;
  return redirect(APPROVED_REDIRECTS.has(nextDestination) ? nextDestination : "/account");
}

export function redirectNearMiss(request: any) {
  const nextDestination = request.query.destination;
  if (!APPROVED_REDIRECTS.has(nextDestination)) {
    console.warn("redirect is outside policy");
  }
  return redirect(nextDestination);
}

export function redirectWithInvertedBlocklist(request: any) {
  const nextDestination = request.query.destination;
  return redirect(
    !REJECTED_REDIRECTS.has(nextDestination) ? "/account" : nextDestination,
  );
}
