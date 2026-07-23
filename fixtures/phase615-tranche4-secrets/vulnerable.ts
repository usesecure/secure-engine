export async function runModel() {
  const providerToken = process.env.MODEL_API_TOKEN;
  console.error('provider failure', providerToken);
  return llm.generate({ diagnostics: providerToken });
}
