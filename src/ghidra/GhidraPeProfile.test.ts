import { expect, it } from "vitest";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import { ghidraPePdbLimitations } from "./GhidraPeProfile.js";
import {
  ghidraPdbLimitations,
  type GhidraSessionInfo,
} from "./GhidraSessionValues.js";

const target: BinaryTarget = {
  path: "/fixture/public.exe",
  sha256: "a".repeat(64),
  kind: "executable",
  format: "pe",
  architecture: "x86_64",
  availableArchitectures: ["x86_64"],
  executableRole: "application",
  managed: false,
  codeView: {
    pdbPath: "public.pdb",
    pdbFileName: "public.pdb",
    guid: "01234567-89ab-cdef-0123-456789abcdef",
    age: 10,
  },
};
const absentAttributes = {
  file: null,
  guid: null,
  age: null,
  signature: null,
  version: null,
  loaded: null,
};

it.each([undefined, absentAttributes])(
  "retains declared identity and unknown load state when reported attributes are %j",
  (pdb) => {
    const caveats = ghidraPePdbLimitations(target, pdb);
    expect(caveats).toHaveLength(1);
    expect(caveats[0]).toContain(
      'PDB "public.pdb" (GUID 01234567-89ab-cdef-0123-456789abcdef, age (decimal) 10)',
    );
    expect(caveats[0]).toContain("load state unknown");
    expect(caveats[0]).not.toContain("were not applied");
    expect(caveats[0]).not.toContain("names are analysis-generated");
  },
);

it.each([true, false, null])(
  "uses reported PDB observations once with loaded = %s",
  (loaded) => {
    const pdb = {
      file: "reported.pdb",
      guid: "reported-guid",
      age: "a",
      signature: null,
      version: "RSDS",
      loaded,
    };
    const caveats = ghidraPePdbLimitations(target, pdb);
    expect(caveats).toEqual(ghidraPdbLimitations(pdb));
    expect(caveats).toHaveLength(1);
    expect(caveats.join(" ")).not.toContain("public.pdb");
  },
);

it("retains explicit failure to load without asserting all names are generated", () => {
  const caveats = ghidraPePdbLimitations(target, {
    ...absentAttributes,
    loaded: false,
  });
  expect(caveats[0]).toContain("reports not loaded");
  expect(caveats[0]).not.toContain("names are analysis-generated");
});

it("retains a loaded-state attestation caveat even when reference attributes are absent", () => {
  const caveats = ghidraPePdbLimitations(target, {
    ...absentAttributes,
    loaded: true,
  });
  expect(caveats).toEqual(
    ghidraPdbLimitations({ ...absentAttributes, loaded: true }),
  );
  expect(caveats[0]).toContain("not an independent PDB identity");
  expect(caveats[0]).not.toContain("reports not loaded");
});

it("preserves omitted-attribute resource coverage with declared fallback identity", () => {
  const pdb: GhidraSessionInfo["pdb"] = {
    ...absentAttributes,
    resource_limit: { omitted_attributes: ["file"], utf16_budget: 2048 },
  };
  const caveats = ghidraPePdbLimitations(target, pdb);
  expect(caveats).toHaveLength(2);
  expect(caveats[0]).toContain("omitted");
  expect(caveats[1]).toContain("public.pdb");
});

it("reports NB10 declared age without inventing a GUID", () => {
  const caveats = ghidraPePdbLimitations(
    {
      ...target,
      codeView: {
        pdbPath: "legacy.pdb",
        pdbFileName: "legacy.pdb",
        guid: null,
        age: 2,
      },
    },
    undefined,
  );
  expect(caveats[0]).toContain('PDB "legacy.pdb" (age (decimal) 2)');
  expect(caveats[0]).not.toContain("GUID");
});

it("retains missing-report uncertainty without a declared CodeView record", () => {
  const { codeView: _, ...withoutReference } = target;
  expect(ghidraPePdbLimitations(withoutReference, undefined)).toEqual(
    ghidraPdbLimitations(undefined),
  );
});

it("adds no PDB warning for a non-PE target", () => {
  const elf: BinaryTarget = {
    path: "/fixture/program",
    sha256: "a".repeat(64),
    kind: "executable",
    format: "elf",
    architecture: "x86_64",
    availableArchitectures: ["x86_64"],
  };
  expect(ghidraPePdbLimitations(elf, undefined)).toEqual([]);
});

it("bounds an escaped inline locator while preserving its declared source value", () => {
  const name = '"'.repeat(5000) + ".pdb";
  const selected = {
    ...target,
    codeView: { ...target.codeView!, pdbFileName: name },
  };
  const caveats = ghidraPePdbLimitations(selected, undefined).join(" ");
  expect(Buffer.byteLength(caveats)).toBeLessThan(1024);
  expect(caveats).toContain("locator omitted");
  expect(caveats).toContain("01234567-89ab-cdef-0123-456789abcdef");
  expect(selected.codeView.pdbFileName).toBe(name);
});
