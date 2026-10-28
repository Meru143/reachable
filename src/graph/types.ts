// CallGraph, CallNode, CallEdge interfaces.
export interface CallNode {
  id: string;
  file: string;
  name: string;
  line: number;
  isEntryPoint: boolean;
}

export interface CallEdge {
  from: string;
  to: string;
  importedFrom: string;
}

export interface CallGraph {
  nodes: Map<string, CallNode>;
  edges: CallEdge[];
  entryPoints: string[];
  /** Packages a project file uses in ways its calls cannot show (ParsedModule.opaque): no verdict about them is UNREACHABLE. */
  opaque?: Set<string>;
  /** Local names project files bind each package to (const _ = require("lodash")): files that are only searched as text
   * are checked for a member read through a computed name on them (_[name]). */
  bindings?: Map<string, Set<string>>;
}
