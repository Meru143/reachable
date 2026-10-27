// Extract vulnerable symbols from advisory data.
import type { Advisory, AdvisoryAffected, VulnSymbol } from "./types.js";

/** A vulnerable symbol, and whether the advisory names it plainly enough to support an UNREACHABLE verdict. */
export type ExtractedSymbol = VulnSymbol & { confident: boolean };

const NAME = String.raw`[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*`;
const CODE = "`[^`\\n]+`";
const CODE_LIST = String.raw`${CODE}(?:\s*,\s*(?:and\s+|or\s+)?${CODE}|\s+(?:and|or)\s+${CODE})*`;
// "via the template function", "in the `zipObjectDeep` function", "through the parse method"
const NAMED_FUNCTION = new RegExp(
  String.raw`\b(?:via|in|of|through|using|calling|by)\s+the\s+(\x60?)(${NAME}(?:\(\))?)\1\s+(?:function|method)\b`,
  "g",
);
// "the `toNumber`, `trim` and `trimEnd` functions", "the `set` function"
const CODE_BEFORE_FUNCTIONS = new RegExp(String.raw`(${CODE_LIST})\s+(?:functions?|methods?)\b`, "g");
// "functions `toNumber`, `trim` and `trimEnd`"
const CODE_AFTER_FUNCTIONS = new RegExp(String.raw`\b(?:functions?|methods?)\s+(${CODE_LIST})`, "g");
// "`_.template`", "_.unset and _.omit"
const UNDERSCORE_MEMBER = new RegExp(String.raw`(?<![\w$.])_\.([A-Za-z_$][\w$]*)`, "g");
// "`foo()`", "`jwt.verify(token, key)`", "matchOne()": as often an internal helper as the API, so never confident.
const CALLED = new RegExp(String.raw`\x60(${NAME})\([^\x60]*\)\x60|(?<![\w$.\x60])(${NAME})\(\)`, "g");

// Globals, Node core modules and keywords: advisories mention them as sinks, payloads or code, never as the
// vulnerable package's own API.
const NOT_PACKAGE_API = new Set([
  "Array", "ArrayBuffer", "BigInt", "Boolean", "Buffer", "Date", "Error", "Function", "JSON", "Map", "Math", "Number",
  "Object", "Promise", "Proxy", "Reflect", "RegExp", "Set", "String", "Symbol", "URL", "URLSearchParams", "Uint8Array",
  "WeakMap", "__proto__", "alert", "apply", "bind", "call", "confirm", "console", "constructor", "decodeURI",
  "decodeURIComponent", "document", "encodeURI", "encodeURIComponent", "escape", "eval", "exports", "fetch",
  "globalThis", "hasOwnProperty", "import", "module", "parseFloat", "parseInt", "process", "prompt", "prototype",
  "require", "setImmediate", "setInterval", "setTimeout", "then", "toString", "unescape", "valueOf", "window",
  "assert", "child_process", "crypto", "dgram", "dns", "events", "fs", "http", "http2", "https", "net", "os", "path",
  "querystring", "readline", "stream", "tls", "url", "util", "vm", "worker_threads", "zlib",
  "catch", "for", "function", "if", "new", "return", "switch", "typeof", "while",
]);
// Words that fill "via the ___ function" without naming one.
const NOT_NAMES = new Set([
  "affected", "another", "callback", "certain", "custom", "default", "exported", "given", "helper", "internal", "main",
  "other", "provided", "public", "same", "specific", "this", "unsafe", "utility", "vulnerable", "wrapper",
]);

function comparable(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, "");
}

// `_.template` -> template, `jwt.verify(token)` -> verify, `Minimatch.prototype.matchOne` -> matchOne; null when
// the reference is not a name the package could export.
function symbolName(reference: string, packageName: string): string | null {
  const bare = reference.trim().replace(/\(.*$/s, "");
  if (!new RegExp(`^${NAME}$`).test(bare)) {
    return null;
  }

  const parts = bare.split(".").filter((part) => !["prototype", "call", "apply", "bind"].includes(part));
  const name = parts[parts.length - 1];
  if (!name || name.length < 2 || NOT_PACKAGE_API.has(name) || NOT_NAMES.has(name.toLowerCase())) {
    return null;
  }

  if (parts.length > 1 && NOT_PACKAGE_API.has(parts[0])) {
    return null;
  }

  // The package's own name (lodash, minimist) names the package, not a function in it.
  return comparable(name) === comparable(packageName.split("/").pop() ?? packageName) ? null : name;
}

/** Function names in the advisory text, each mapped to whether the wording makes it confident. */
function textSymbols(advisory: Advisory, packageName: string): Map<string, boolean> {
  // Code samples call whatever reproduces the bug (console.log, Date.now, the package itself).
  const details = (advisory.details ?? "").replace(/```[\s\S]*?(?:```|$)/g, "\n\n");
  const leadParagraph = details
    .split(/\n\s*\n/)
    .map((paragraph) => paragraph.trim())
    .find((paragraph) => paragraph.length > 0 && !paragraph.startsWith("#"));
  const fullText = `${advisory.summary ?? ""}\n\n${details}`;
  const symbols = new Map<string, boolean>();

  const add = (reference: string, confident: boolean): void => {
    const name = symbolName(reference, packageName);
    if (name) {
      // A call such as `setKey()` reads like a code location, not the API, even after "function".
      symbols.set(name, symbols.get(name) === true || (confident && !reference.includes("(")));
    }
  };

  for (const match of fullText.matchAll(NAMED_FUNCTION)) {
    add(match[2], true);
  }

  for (const pattern of [CODE_BEFORE_FUNCTIONS, CODE_AFTER_FUNCTIONS]) {
    for (const match of fullText.matchAll(pattern)) {
      for (const code of match[1].matchAll(/`([^`]+)`/g)) {
        add(code[1], true);
      }
    }
  }

  for (const match of fullText.matchAll(UNDERSCORE_MEMBER)) {
    add(match[1], true);
  }

  // Calls only from the summary and lead paragraph: deeper write-ups walk through internals.
  for (const match of `${advisory.summary ?? ""}\n\n${leadParagraph ?? ""}`.matchAll(CALLED)) {
    add(match[1] ?? match[2], false);
  }

  return symbols;
}

function advisoryGhsaId(advisory: Advisory): string {
  return advisory.aliases?.find((alias) => alias.startsWith("GHSA-")) ?? advisory.id;
}

function advisoryCvssScore(advisory: Advisory): number {
  const explicitScore = advisory.database_specific?.cvss?.score;
  if (typeof explicitScore === "number") {
    return explicitScore;
  }

  for (const severity of advisory.severity ?? []) {
    if (!severity.score) {
      continue;
    }

    const parsed = Number(severity.score);
    if (!Number.isNaN(parsed)) {
      return parsed;
    }

    const vectorMatch = severity.score.match(/CVSS:[0-9.]+\/.*?([0-9]+\.[0-9]+)/);
    if (vectorMatch) {
      const vectorScore = Number(vectorMatch[1]);
      if (!Number.isNaN(vectorScore)) {
        return vectorScore;
      }
    }
  }

  // ponytail: OSV gives CVSS as a vector, so the score is the floor of GitHub's severity band (HIGH -> 7.0);
  // compute the CVSS base score from the vector if exact scores matter.
  switch ((advisory.database_specific?.severity ?? "").toUpperCase()) {
    case "CRITICAL":
      return 9.0;
    case "HIGH":
      return 7.0;
    case "MODERATE":
    case "MEDIUM":
      return 4.0;
    case "LOW":
      return 1.0;
    default:
      return 0;
  }
}

function severityFromScore(score: number): VulnSymbol["severity"] {
  if (score >= 9.0) {
    return "CRITICAL";
  }

  if (score >= 7.0) {
    return "HIGH";
  }

  if (score >= 4.0) {
    return "MODERATE";
  }

  return "LOW";
}

function versionRange(affected: AdvisoryAffected): string {
  return (affected.ranges ?? [])
    .map((range) => (range.events ?? []).map((event) => Object.entries(event).map(([key, value]) => `${key}:${value}`).join(",")).join(" -> "))
    .filter((range) => range.length > 0)
    .join("; ");
}

/** One row per vulnerable symbol of `packageName` (the installed npm package the advisory was found for). */
export function extractVulnSymbols(advisory: Advisory, packageName: string): ExtractedSymbol[] {
  const cvssScore = advisoryCvssScore(advisory);
  const severity = severityFromScore(cvssScore);
  const ghsaId = advisoryGhsaId(advisory);
  // An advisory also lists sibling packages (lodash-es, lodash.template) and other ecosystems; only the
  // installed package's entries apply.
  const entries = (advisory.affected ?? []).filter(
    (affected) => affected.package?.name === packageName && affected.package?.ecosystem === "npm",
  );
  const affectedVersionRange = entries.map(versionRange).filter((range) => range.length > 0).join("; ");
  const symbols = new Map<string | null, boolean>();

  for (const entry of entries) {
    for (const imported of entry.ecosystem_specific?.imports ?? []) {
      const references = imported.symbols?.length
        ? imported.symbols
        : imported.name
          ? [imported.name]
          : imported.path
            ? [imported.path.split(".").pop() ?? imported.path]
            : [];
      if (references.length === 0) {
        symbols.set(null, false);
      }

      for (const reference of references) {
        const name = symbolName(reference, packageName);
        symbols.set(name, name !== null);
      }
    }
  }

  if (symbols.size === 0) {
    for (const [name, confident] of textSymbols(advisory, packageName)) {
      symbols.set(name, confident);
    }
  }

  if (symbols.size === 0) {
    symbols.set(null, false);
  }

  return [...symbols].map(([exportedSymbol, confident]) => ({
    package: packageName,
    ghsaId,
    cvssScore,
    severity,
    exportedSymbol,
    affectedVersionRange,
    confident,
  }));
}
