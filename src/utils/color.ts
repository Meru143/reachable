// chalk for stdout. chalk reads the terminal and FORCE_COLOR, and leaves NO_COLOR (https://no-color.org) to the app;
// FORCE_COLOR overrides NO_COLOR, as in Node.
import { Chalk, supportsColor } from "chalk";

const level = process.env.NO_COLOR && process.env.FORCE_COLOR === undefined ? 0 : supportsColor ? supportsColor.level : 0;

export const chalk = new Chalk({ level });
