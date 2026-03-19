import Parser from "tree-sitter";
import JavaScript from "tree-sitter-javascript";
import { describe, expect, it } from "vitest";

import {
  extractCallSites,
  extractDynamicImports,
  extractESMImports,
  extractExports,
  extractRequireCalls,
} from "../../src/parser/javascript.js";

const parser = new Parser();
parser.setLanguage(JavaScript);

function parse(sourceText: string): Parser.Tree {
  return parser.parse(sourceText);
}

describe("parser/javascript", () => {
  it("extracts require() calls from CJS source", () => {
    const tree = parse(`
      const express = require("express");
      const fs = require("node:fs");
    `);

    expect(extractRequireCalls(tree)).toEqual([
      { source: "express", kind: "require", line: 2, isTypeOnly: false },
      { source: "node:fs", kind: "require", line: 3, isTypeOnly: false },
    ]);
  });

  it("extracts import statements from ESM source", () => {
    const tree = parse(`
      import express from "express";
      import { join } from "node:path";
    `);

    expect(extractESMImports(tree)).toEqual([
      { source: "express", kind: "esm", line: 2, isTypeOnly: false },
      { source: "node:path", kind: "esm", line: 3, isTypeOnly: false },
    ]);
  });

  it("extracts dynamic import() calls", () => {
    const tree = parse(`
      async function load() {
        const feature = await import("./feature.js");
        return import("lodash");
      }
    `);

    expect(extractDynamicImports(tree)).toEqual([
      { source: "./feature.js", kind: "dynamic", line: 3, isTypeOnly: false },
      { source: "lodash", kind: "dynamic", line: 4, isTypeOnly: false },
    ]);
  });

  it("extracts identifier and member-expression call sites", () => {
    const tree = parse(`
      handler();
      app.use(express.json());
      object.method();
    `);

    const callees = extractCallSites(tree).map((call) => call.callee);

    expect(callees).toContain("handler");
    expect(callees).toContain("app.use");
    expect(callees).toContain("express.json");
    expect(callees).toContain("object.method");
  });

  it("captures wildcard re-export metadata", () => {
    const tree = parse(`
      export * from "./leaf";
    `);

    expect(extractExports(tree)).toEqual([
      { name: "*", line: 2, source: "./leaf", isWildcard: true },
    ]);
  });
});
