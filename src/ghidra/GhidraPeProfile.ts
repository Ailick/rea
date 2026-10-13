import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import {
  ghidraPdbLimitations,
  type GhidraSessionInfo,
} from "./GhidraSessionValues.js";

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
  const locator =
    pdbFileName.length * 6 + 2 <= 1024
      ? JSON.stringify(pdbFileName)
      : "(declared locator omitted from this inline caveat: 1024-byte resource budget)";
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
