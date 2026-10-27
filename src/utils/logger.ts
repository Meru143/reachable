// pino logger with --verbose flag. Logs go to stderr so they never mix with JSON, SARIF or markdown on stdout.
import pino from "pino";

const defaultLevel = process.env.LOG_LEVEL ?? "warn";
const transport = process.stderr.isTTY
  ? pino.transport({
      target: "pino-pretty",
      options: {
        colorize: !process.env.NO_COLOR,
        destination: 2,
      },
    })
  : pino.destination(2);

export const logger = pino(
  {
    level: defaultLevel,
  },
  transport,
);

export function setVerbose(val: boolean): void {
  logger.level = val ? "debug" : defaultLevel;
}
