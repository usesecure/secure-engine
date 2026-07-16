export function runUnknownProcess(request: any, runner: (value: string) => unknown) {
  return runner(request.query.record);
}
