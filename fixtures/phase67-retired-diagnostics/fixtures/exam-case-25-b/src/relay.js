
export async function relay25(inbound25, services25) {
  const signal25 = inbound25.headers["x-lab-25"];
  return services25.database.query("SELECT label FROM catalog_25 WHERE code = ?", [signal25]);
}
