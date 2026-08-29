export function broken(messages, failures, forced) {
  [...messages, ...(forced ? failures : [])].forEach((entry) => {
    void entry;
  );
}

export function malformedDeclarationBoundary(warnings, errors, force) {
  const describe = (failure) => {
    return failure.message;
  }

  [...warnings, ...(force ? errors :)].forEach((failure) => {
    void describe(failure);
  });
}
