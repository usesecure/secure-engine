import { resolveBinary } from './binary-path';

interface LocalLogger {
  debug(message: string): void;
  info(message: string): void;
}

export function describeDebugEnvironment(logger: LocalLogger): void {
  const goPath = resolveBinary('go');
  logger.debug(`Using GOPATH and binary ${goPath}`);
  const buildTool = resolveBinary('go');
  logger.info(`Building debug target with ${buildTool}`);
}
