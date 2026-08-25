import { resolveBinary } from './binary-path';

interface WorkspaceConfiguration {
  get<T>(key: string): T | undefined;
}

export function runLint(goConfig: WorkspaceConfiguration): string | undefined {
  const linter = goConfig.get<string>('lintTool');
  return linter === undefined ? undefined : resolveBinary(linter);
}
