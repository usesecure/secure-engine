"use server";

declare const accountStore: {
  update(input: unknown): Promise<void>;
  archive(input: unknown): Promise<void>;
};

export async function updateWithoutAuthorization(payload: any) {
  await accountStore.update(payload);
}

async function archiveAccount(payload: any) {
  await accountStore.archive(payload);
}

export async function archiveThroughHelper(payload: any) {
  await archiveAccount(payload);
}

function enforceMembership(actor: any) {
  if (!actor.permissions.includes("account:write")) {
    throw new Error("membership does not grant this operation");
  }
}

export async function updateWithHelperGuard(payload: any) {
  enforceMembership(payload.actor);
  await accountStore.update(payload.change);
}

async function applyAuthorizedUpdate(change: unknown) {
  await accountStore.update(change);
}

export async function updateThroughGuardedMutationHelper(payload: any) {
  enforceMembership(payload.actor);
  await applyAuthorizedUpdate(payload.change);
}

export async function updateWithNearMissGuard(payload: any) {
  if (!payload.actor.permissions.includes("account:write")) {
    console.warn("membership check failed");
  }
  await accountStore.update(payload.change);
}

async function inlineArchiveAction(payload: any) {
  "use server";
  await accountStore.archive(payload);
}

export const exposeInlineArchive = inlineArchiveAction;
