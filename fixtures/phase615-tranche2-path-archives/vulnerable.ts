import path from 'node:path';

export async function unpackBundle(archive: BundleArchive, root: string) {
  for (const entry of archive.entries()) {
    await fs.writeFile(path.join(root, entry.path), entry.bytes);
  }
}
