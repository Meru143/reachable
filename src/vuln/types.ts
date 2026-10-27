// Advisory, VulnSymbol, ReachabilityResult types.
export interface AdvisoryImport {
  path?: string;
  name?: string;
  symbols?: string[];
}

export interface AdvisoryAffected {
  package?: {
    name?: string;
    ecosystem?: string;
  };
  ranges?: Array<{
    type?: string;
    events?: Array<Record<string, string>>;
  }>;
  ecosystem_specific?: {
    imports?: AdvisoryImport[];
  };
}

export interface AdvisorySeverity {
  type?: string;
  score?: string;
}

export interface Advisory {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  severity?: AdvisorySeverity[];
  affected?: AdvisoryAffected[];
  database_specific?: {
    severity?: string;
    cvss?: {
      score?: number;
    };
  };
}

export interface InstalledPackage {
  name: string;
  version: string;
  ecosystem: string;
  dev?: boolean;
  /** Installed under another package (node_modules/a/node_modules/b): only that package's code loads this copy. */
  nested?: boolean;
}

export interface VulnSymbol {
  package: string;
  ghsaId: string;
  cvssScore: number;
  severity: "CRITICAL" | "HIGH" | "MODERATE" | "LOW";
  exportedSymbol: string | null;
  affectedVersionRange: string;
}

/** Why a result is UNKNOWN; the README's Limitations section explains each one. */
export type UnknownReason =
  | "lookup-failed"
  | "not-imported"
  | "symbol-unknown"
  | "transitive"
  | "symbol-unconfirmed"
  | "unresolved-reference";

export interface ReachabilityResult {
  advisory: VulnSymbol;
  status: "REACHABLE" | "UNREACHABLE" | "UNKNOWN";
  callPath: string[] | null;
  /** Set on UNKNOWN results only. */
  reason?: UnknownReason;
}
