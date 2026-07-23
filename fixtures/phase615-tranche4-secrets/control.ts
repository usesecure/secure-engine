export async function runModel(prompt: string) {
  console.error('provider failure', { provider: 'primary', redacted: true });
  return llm.generate({ prompt });
}
