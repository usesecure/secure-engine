interface ExtensionState {
  get<T>(key: string, fallback: T): T;
}

export function getFromGlobalState<T>(state: ExtensionState, key: string, fallback: T): T {
  return state.get(key, fallback);
}

export function showSurveyState(state: ExtensionState): void {
  const saved = getFromGlobalState(state, 'survey-state', {});
  console.log(`Survey diagnostic state: ${JSON.stringify(saved)}`);
}
