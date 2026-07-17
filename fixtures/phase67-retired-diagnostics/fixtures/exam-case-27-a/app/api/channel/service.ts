
export async function conduit27(signal27: string, services27: any) {
  return services27.database.query("SELECT label FROM catalog_27 WHERE code = '" + signal27 + "'");
}
