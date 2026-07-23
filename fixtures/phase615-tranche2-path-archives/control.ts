import path from 'node:path';

export async function unpackBundle(archive: BundleArchive, root: string) {
  for (const entry of archive.entries()) {
    const generatedName = crypto.randomUUID();
    await fs.writeFile(path.join(root, generatedName), entry.bytes);
  }
}
