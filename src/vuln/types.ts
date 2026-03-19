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
}

export interface VulnSymbol {
  package: string;
  ghsaId: string;
  cvssScore: number;
  severity: "CRITICAL" | "HIGH" | "MODERATE" | "LOW";
  exportedSymbol: string | null;
  affectedVersionRange: string;
}

export interface ReachabilityResult {
  advisory: VulnSymbol;
  status: "REACHABLE" | "UNREACHABLE" | "UNKNOWN";
  callPath: string[] | null;
}
