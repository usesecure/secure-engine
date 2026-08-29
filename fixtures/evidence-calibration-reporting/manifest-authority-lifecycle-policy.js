const lifecycleQueue = [];

function evaluateAuthorityPolicy(dependency, authorityPolicy) {
  return authorityPolicy.allows(dependency);
}

export function bypassesLifecycleAuthority(dependency, authorityPolicy) {
  const permitted =
    dependency.isShortcut || evaluateAuthorityPolicy(dependency, authorityPolicy) === true;
  if (permitted) {
    lifecycleQueue.push(dependency);
  }
}

export function bindsLifecycleAuthority(dependency, authorityPolicy) {
  const permitted = evaluateAuthorityPolicy(dependency.target, authorityPolicy) === true;
  if (permitted) {
    lifecycleQueue.push(dependency);
  }
}

export function incompleteArtifactScope(resource, configuredBase) {
  const candidate = new URL(resource);
  const authority = new URL(configuredBase);
  return candidate.hostname === authority.hostname;
}

export function completeArtifactScope(resource, configuredBase) {
  const candidate = new URL(resource);
  const authority = new URL(configuredBase);
  const prefix = authority.pathname.endsWith('/')
    ? authority.pathname
    : `${authority.pathname}/`;
  return (
    candidate.origin === authority.origin &&
    (prefix === '/' || candidate.pathname.startsWith(prefix))
  );
}

export async function policyLoadedAfterHigherAuthorityInstall(
  requested,
  installer,
  loadAuthorityPolicy,
) {
  await installer.apply({ add: requested });
  const authorityPolicy = await loadAuthorityPolicy();
  await installer.apply({ add: requested, authorityPolicy });
}

export async function policyBoundAcrossInstallScopes(
  requested,
  installer,
  loadAuthorityPolicy,
) {
  const authorityPolicy = await loadAuthorityPolicy();
  await installer.preflight({ add: requested, authorityPolicy });
  await installer.apply({ add: requested, authorityPolicy });
}
