import Parser from "tree-sitter";
import JavaScript from "tree-sitter-javascript";
import { describe, expect, it } from "vitest";

import {
  extractCallSites,
  extractDynamicImports,
  extractESMImports,
  extractExports,
  extractOpaqueSpecifiers,
  extractRequireCalls,
  extractUsedNamesWithLanguage,
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

  it("lists the names a module uses beyond declaring them or exporting them under the same name", () => {
    const used = extractUsedNamesWithLanguage(
      parse(`
        import { imported } from "./x";
        import { importedAs as localName } from "./y";
        function declared() {}
        export function namedExport() {}
        export { declared };
        export { exportedAs as otherName };
        module.exports = { shorthand, same: same, key: valueOfOtherKey };
        exports.bound = bound;
        lib.alsoBound = alsoBound;
        lib.otherName = renamed;
        called();
        obj.method();
        const alias = aliased;
        list.map(passed);
        read.property;
        handlers["dispatched"]();
        export default defaulted;
      `),
      JavaScript,
    );
    const defaultDeclaration = extractUsedNamesWithLanguage(parse("export default function declaredDefault() {}\n"), JavaScript);

    for (const name of ["importedAs", "exportedAs", "valueOfOtherKey", "renamed", "called", "method", "aliased", "passed", "property", "dispatched", "defaulted"]) {
      expect(used).toContain(name);
    }
    for (const name of ["imported", "localName", "declared", "namedExport", "otherName", "shorthand", "same", "key", "bound", "alsoBound", "alias"]) {
      expect(used).not.toContain(name);
    }
    expect(defaultDeclaration).toContain("declaredDefault");
  });

  it("does not count uses of a module the call graph sees as opaque", () => {
    const opaque = extractOpaqueSpecifiers(
      parse(`
        const _ = require("lodash");
        import fp from "lodash/fp";
        import * as lo from "lodash";
        const debug = require("debug")("app");
        require("dotenv").config();
        import "./side-effect";
        _.map([1], String);
        _["map"]([1], String);
        _([1]).value();
        lo?.map([1], String);
        fp.map(String);
        const { trim, pad: padStart } = _;
        const lib = _;
        lib.chunk([1, 2], 1);
        if (typeof _ === "function" && !lo) [1].map((_, i) => i);
        for (const lo of [1]) count += 1;
        const { default: lazy } = await import("lodash");
        lazy.map([1], String);
        (await import("lodash")).default.map([1], String);
        require("lodash").default.map([1], String);
        require("lodash")["default"].map([1], String);
        import("lodash");
        const wrapped = await (import("lodash"));
        wrapped.map([1], String);
      `),
    );

    expect(opaque).not.toContain("lodash");
    expect(opaque).not.toContain("lodash/fp");
    expect(opaque).not.toContain("debug");
  });

  it.each([
    ["a computed member (f13-computed)", 'const _ = require("lodash");\nconst fn = "temp" + "late";\n_[fn]("x");'],
    ["a copy (h-twig)", 'const _ = require("lodash");\nres.locals.lib = Object.assign({}, _);'],
    ["an assignment", 'const _ = require("lodash");\napp.locals.lib = _;'],
    ["an argument (h-ns-passed)", 'const _ = require("lodash");\nrender(_, "Hi");'],
    ["a shorthand property", 'const _ = require("lodash");\nres.render("index", { _ });'],
    ["another name, then handed on", 'const lib = require("lodash");\nconst helpers = lib;\nmodule.exports = { helpers };'],
    ["a rest pattern", 'const _ = require("lodash");\nconst { map, ...rest } = _;\nmodule.exports = rest;'],
    ["enumeration", 'const _ = require("lodash");\nfor (const key in _) console.log(key);'],
    ["a fallback", 'const lib = globalThis._ || require("lodash");'],
    ["a default export", 'import _ from "lodash";\nexport default _;'],
    ["an exported name", 'import * as _ from "lodash";\nexport const lib = _;'],
    ["an export list", 'import * as _ from "lodash";\nexport { _ };'],
    ["module.exports (h-barrel-cjs)", 'module.exports = require("lodash");'],
    ["export * (h-barrel-star-ts)", 'export * from "lodash";'],
    ["a re-exported default", 'export { default as lib } from "lodash";'],
    ["an awaited import()", 'const lib = await import("lodash");\nregister(lib);'],
    ["a promise chain", 'import("lodash").then(render);'],
    ["a promise chain in brackets", 'import("lodash")["then"](render);'],
    ["a promise kept for later", 'const pending = import("lodash");\npending.then(render);'],
    ["a promise chain in parentheses", '(import("lodash")).then(render);'],
    ["a promise chain spelled with an escape", 'import("lodash").th\\u{65}n(render);'],
    ["a destructured default spelled with an escape", 'const { \\u{64}efault: lib } = require("lodash");\nregister(lib);'],
    ["a default import by its string name", 'import { "default" as lib } from "lodash";\nregister(lib);'],
    ["a re-exported default spelled with an escape", 'export { \\u{64}efault } from "lodash";'],
    ["a promise returned", "export const load = () => import(\"lodash\");"],
    ["its name with escapes", 'render("\\u006codash", text);\nrender("lo\\x64ash", text);'],
    ["the default property in brackets", 'const lib = require("lodash")["default"];\napp.locals.lib = lib;'],
    ["an escaped member name", 'const _ = require("lodash");\n_["temp\\x6cate"]("x");'],
    ["a binding spelled with an escape", 'const \\u{5f} = require("lodash");\napp.locals.lib = _;'],
    ["a default import by name", 'import { default as lib, map } from "lodash";\nregister(lib, map);'],
    ["a destructured default", 'const { default: lib } = await import("lodash");\nregister(lib);'],
    ["the default property", 'const lib = require("lodash").default;\napp.locals.lib = lib;'],
    ["its name, to a dependency (h-computed-spec)", 'const render = require("tplkit");\nrender("lodash", "Hi <%= n %>");'],
    ["its name, to createRequire (h-createrequire)", 'const load = createRequire(import.meta.url);\nload("lodash/template");'],
    ["its name in a template literal", "const name = `lodash`;\nawait import(name);"],
  ])("lists a module used through %s as opaque", (_label, source) => {
    expect(extractOpaqueSpecifiers(parse(source))).toEqual(expect.arrayContaining([expect.stringMatching(/^lodash(\/template)?$/)]));
  });
});
