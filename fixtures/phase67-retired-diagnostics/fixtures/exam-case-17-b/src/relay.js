
export async function relay17(inbound17, services17) {
  const signal17 = inbound17.headers["x-lab-17"];
  const destination17 = new URL(signal17);
  if (destination17.protocol !== "https:" || destination17.hostname !== "api17.example.test") throw new Error("blocked-17");
  return fetch(destination17);
}
