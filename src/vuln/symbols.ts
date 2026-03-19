// Extract vulnerable symbols from advisory data.
import type { Advisory, VulnSymbol } from "./types.js";

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

function affectedVersionRange(advisory: Advisory, affectedIndex: number): string {
  const affected = advisory.affected?.[affectedIndex];
  const ranges = affected?.ranges ?? [];
  const serializedRanges = ranges
    .map((range) => (range.events ?? []).map((event) => Object.entries(event).map(([key, value]) => `${key}:${value}`).join(",")).join(" -> "))
    .filter((range) => range.length > 0);

  return serializedRanges.join("; ");
}

function regexSymbol(advisory: Advisory): string | null {
  const details = advisory.details ?? "";
  const contextualMatch = details.match(/(?:vulnerable|affected)[^`"'A-Za-z0-9_$]*[`"']([A-Za-z_$][\w$.]*)\(?[`"']?/i);
  if (contextualMatch) {
    return contextualMatch[1];
  }

  const fallbackMatch = details.match(/[`"']([A-Za-z_$][\w$.]*)\(?[`"']/);
  return fallbackMatch ? fallbackMatch[1] : null;
}

export function extractVulnSymbols(advisory: Advisory): VulnSymbol[] {
  const cvssScore = advisoryCvssScore(advisory);
  const severity = severityFromScore(cvssScore);
  const ghsaId = advisoryGhsaId(advisory);
  const extracted: VulnSymbol[] = [];

  for (const [index, affected] of (advisory.affected ?? []).entries()) {
    const packageName = affected.package?.name ?? "unknown";
    const imports = affected.ecosystem_specific?.imports ?? [];

    if (imports.length > 0) {
      for (const entry of imports) {
        const symbols = entry.symbols?.length ? entry.symbols : entry.name ? [entry.name] : entry.path ? [entry.path.split(".").pop() ?? entry.path] : [];

        if (symbols.length === 0) {
          extracted.push({
            package: packageName,
            ghsaId,
            cvssScore,
            severity,
            exportedSymbol: null,
            affectedVersionRange: affectedVersionRange(advisory, index),
          });
          continue;
        }

        for (const symbol of symbols) {
          extracted.push({
            package: packageName,
            ghsaId,
            cvssScore,
            severity,
            exportedSymbol: symbol ?? null,
            affectedVersionRange: affectedVersionRange(advisory, index),
          });
        }
      }
      continue;
    }

    extracted.push({
      package: packageName,
      ghsaId,
      cvssScore,
      severity,
      exportedSymbol: regexSymbol(advisory),
      affectedVersionRange: affectedVersionRange(advisory, index),
    });
  }

  if (extracted.length > 0) {
    return extracted;
  }

  return [
    {
      package: "unknown",
      ghsaId,
      cvssScore,
      severity,
      exportedSymbol: regexSymbol(advisory),
      affectedVersionRange: "",
    },
  ];
}
