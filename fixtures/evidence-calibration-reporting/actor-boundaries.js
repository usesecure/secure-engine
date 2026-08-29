export async function processAuthority(secret) {
  const destination = process.env.REMOTE_ENDPOINT;
  if (destination) {
    await fetch(destination, { headers: { authorization: `Bearer ${secret}` } });
  }
}

export async function lowerPrivilegeBoundary(request) {
  const destination = request.query.destination;
  await fetch(destination);
}

export async function renamedLowerPrivilegeBoundary(message) {
  const endpoint = message.query.destination;
  await fetch(endpoint);
}
