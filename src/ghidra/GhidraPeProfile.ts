import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import {
  ghidraPdbLimitations,
  type GhidraSessionInfo,
} from "./GhidraSessionValues.js";

const PDB_LOCATOR_INLINE_BYTE_BUDGET = 1024;

/** Measure JSON quotes, escapes and UTF-8 without allocating the encoded string. */
const pdbLocatorFitsInlineBudget = (value: string): boolean => {
  if (value.length * 6 + 2 <= PDB_LOCATOR_INLINE_BYTE_BUDGET) return true;
  if (value.length + 2 > PDB_LOCATOR_INLINE_BYTE_BUDGET) return false;
  let bytes = 2;
  for (let index = 0; index < value.length; index += 1) {
    const point = value.codePointAt(index) ?? 0;
    if (point > 0xffff) {
      bytes += 4;
      index += 1;
    } else if (point >= 0xd800 && point <= 0xdfff) {
      // JSON.stringify escapes unpaired UTF-16 surrogates as six ASCII bytes.
      bytes += 6;
    } else if (point < 0x20) {
      bytes +=
        point === 8 ||
        point === 9 ||
        point === 10 ||
        point === 12 ||
        point === 13
          ? 2
          : 6;
    } else if (point === 0x22 || point === 0x5c) {
      bytes += 2;
    } else {
      bytes += point < 0x80 ? 1 : point < 0x800 ? 2 : 3;
    }
    if (bytes > PDB_LOCATOR_INLINE_BYTE_BUDGET) return false;
  }
  return true;
};

/** Use reported Program facts first, retaining declared PE facts as a fallback. */
export const ghidraPePdbLimitations = (
  target: BinaryTarget,
  pdb: GhidraSessionInfo["pdb"],
): readonly string[] => {
  if (target.format !== "pe") return [];
  const reported = ghidraPdbLimitations(pdb);
  if (
    target.codeView === undefined ||
    (pdb !== undefined &&
      pdb.file !== null &&
      pdb.age !== null &&
      (target.codeView.guid === null || pdb.guid !== null))
  )
    return reported;
  const { pdbFileName, guid, age } = target.codeView;
  // Include JSON escaping in the inline budget before allocating that representation.
  const locator = pdbLocatorFitsInlineBudget(pdbFileName)
    ? JSON.stringify(pdbFileName)
    : `(declared locator omitted from this inline caveat: ${PDB_LOCATOR_INLINE_BYTE_BUDGET}-byte resource budget)`;
  const identity =
    guid === null
      ? `age (decimal) ${age}`
      : `GUID ${guid}, age (decimal) ${age}`;
  const state =
    pdb === undefined
      ? "Ghidra did not report PDB attributes; load state unknown"
      : pdb.loaded === false
        ? "Ghidra reports not loaded"
        : pdb.loaded === true
          ? "Ghidra reports a loaded PDB; this declared identity is not an independent matching-PDB attestation"
          : "Ghidra reports load state unknown";
  const declared = `The PE CodeView record references PDB ${locator} (${identity}); ${state}. Original PDB names and types may be missing. Use list_procedures and address-based analysis to inspect recovered functions. REA does not admit a caller-selected PDB companion.`;
  return pdb === undefined ? [declared] : [...reported, declared];
};
