// Where Gig Guard keeps its private files (ledger, audit log). Never inside the repository:
// GG_DATA_DIR, or ~/.gig-guard by default. GG_LEDGER / GG_AUDIT still override single files.
import os from "node:os";
import path from "node:path";
import fs from "node:fs";
export const DATA_DIR = process.env.GG_DATA_DIR || path.join(os.homedir(), ".gig-guard");
export const dataFile = (name) => path.join(DATA_DIR, name);
export function ensureDir(file) { fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true, mode: 0o700 }); }
