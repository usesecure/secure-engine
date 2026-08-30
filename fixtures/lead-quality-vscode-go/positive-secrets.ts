function identity(value: string | undefined): string | undefined {
  return value;
}

export function localSecretControl(): void {
  const secret = process.env.MODEL_API_TOKEN;
  const forwarded = identity(secret);
  console.error('Provider setup failed', forwarded);
}

export function cleanSharedHelperControl(): void {
  const publicValue = identity('public-region');
  console.info(publicValue);
}

export async function remoteSecretControl(llm: { generate(value: unknown): Promise<unknown> }): Promise<unknown> {
  const credential = process.env.MODEL_SERVICE_SECRET;
  return llm.generate({ credential });
}
