// Constructs CallGraph from parsed ASTs.
import path from "node:path";

import { parseFile } from "../parser/index.js";
import { resolveImport } from "../parser/resolver.js";
import { logger } from "../utils/logger.js";
import type { CallGraph, CallNode } from "./types.js";

function normalizeFilePath(filePath: string, cwd: string): string {
  return path.relative(cwd, filePath).replace(/\\/g, "/");
}

function moduleNodeId(filePath: string, cwd: string): string {
  return `${normalizeFilePath(filePath, cwd)}::module`;
}

function exportNodeId(filePath: string, exportName: string, cwd: string): string {
  return `${normalizeFilePath(filePath, cwd)}::${exportName}`;
}

function callNodeId(filePath: string, callee: string, line: number, cwd: string): string {
  return `${normalizeFilePath(filePath, cwd)}::call:${callee}:${line}`;
}

function packageNodeId(packageName: string): string {
  return `pkg:${packageName}::module`;
}

function isTestFile(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, "/");
  return /\.test\.[cm]?[jt]sx?$/.test(normalized) || /\.spec\.[cm]?[jt]sx?$/.test(normalized) || normalized.includes("/__tests__/");
}

function isSourceFile(filePath: string): boolean {
  return /\.[cm]?[jt]sx?$/.test(filePath);
}

function ensureNode(graph: CallGraph, node: CallNode): void {
  if (!graph.nodes.has(node.id)) {
    graph.nodes.set(node.id, node);
  }
}

function addEdge(graph: CallGraph, edge: { from: string; to: string; importedFrom: string }, edgeSet: Set<string>): void {
  const edgeKey = `${edge.from}->${edge.to}:${edge.importedFrom}`;
  if (edgeSet.has(edgeKey)) {
    return;
  }

  edgeSet.add(edgeKey);
  graph.edges.push(edge);
}

export function buildGraph(files: string[], entryPoints: string[], cwd: string): CallGraph {
  const includeTests = process.argv.includes("--include-tests");
  const graph: CallGraph = {
    nodes: new Map(),
    edges: [],
    entryPoints: [],
  };
  const edgeSet = new Set<string>();
  const visitedFiles = new Set<string>();
  const inProgressFiles = new Set<string>();
  const absoluteEntries = new Set(entryPoints.map((entry) => path.resolve(cwd, entry)));

  function visitFile(filePath: string): void {
    const absoluteFile = path.resolve(cwd, filePath);

    if (!includeTests && isTestFile(absoluteFile)) {
      return;
    }

    if (inProgressFiles.has(absoluteFile)) {
      logger.warn({ file: absoluteFile }, "Circular import detected");
      return;
    }

    if (visitedFiles.has(absoluteFile)) {
      return;
    }

    inProgressFiles.add(absoluteFile);
    visitedFiles.add(absoluteFile);

    const parsed = parseFile(absoluteFile);
    const relativeFile = normalizeFilePath(absoluteFile, cwd);
    const currentModuleId = moduleNodeId(absoluteFile, cwd);

    ensureNode(graph, {
      id: currentModuleId,
      file: relativeFile,
      name: "module",
      line: 1,
      isEntryPoint: absoluteEntries.has(absoluteFile),
    });

    if (absoluteEntries.has(absoluteFile) && !graph.entryPoints.includes(currentModuleId)) {
      graph.entryPoints.push(currentModuleId);
    }

    for (const exportedSymbol of parsed.exports) {
      const exportedNodeId = exportNodeId(absoluteFile, exportedSymbol.name, cwd);
      ensureNode(graph, {
        id: exportedNodeId,
        file: relativeFile,
        name: exportedSymbol.name,
        line: exportedSymbol.line,
        isEntryPoint: false,
      });
      addEdge(graph, { from: currentModuleId, to: exportedNodeId, importedFrom: relativeFile }, edgeSet);
    }

    for (const call of parsed.calls) {
      const calleeNodeId = callNodeId(absoluteFile, call.callee, call.line, cwd);
      ensureNode(graph, {
        id: calleeNodeId,
        file: relativeFile,
        name: call.callee,
        line: call.line,
        isEntryPoint: false,
      });
      addEdge(graph, { from: currentModuleId, to: calleeNodeId, importedFrom: relativeFile }, edgeSet);
    }

    for (const importedModule of parsed.imports.filter((entry) => !entry.isTypeOnly)) {
      const resolvedImport = resolveImport(importedModule.source, absoluteFile, cwd);

      if (!resolvedImport) {
        continue;
      }

      if (!path.isAbsolute(resolvedImport)) {
        const packageId = packageNodeId(resolvedImport);
        ensureNode(graph, {
          id: packageId,
          file: resolvedImport,
          name: resolvedImport,
          line: importedModule.line,
          isEntryPoint: false,
        });
        addEdge(graph, { from: currentModuleId, to: packageId, importedFrom: importedModule.source }, edgeSet);
        continue;
      }

      if (!isSourceFile(resolvedImport)) {
        continue;
      }

      const targetModuleId = moduleNodeId(resolvedImport, cwd);
      ensureNode(graph, {
        id: targetModuleId,
        file: normalizeFilePath(resolvedImport, cwd),
        name: "module",
        line: importedModule.line,
        isEntryPoint: absoluteEntries.has(resolvedImport),
      });
      addEdge(graph, { from: currentModuleId, to: targetModuleId, importedFrom: importedModule.source }, edgeSet);
      visitFile(resolvedImport);
    }

    inProgressFiles.delete(absoluteFile);
  }

  for (const entryPoint of absoluteEntries) {
    visitFile(entryPoint);
  }

  for (const filePath of files) {
    visitFile(filePath);
  }

  return graph;
}
