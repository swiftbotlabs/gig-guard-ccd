// File inputs (a deliverable to review, a terms file) are read only from inside the workspace:
// GG_WORKSPACE, or the directory Gig Guard was started in. Their text is sent to paid reviewers,
// so a path like /etc/passwd or ../../secrets must never get that far.
import fs from "node:fs";
import path from "node:path";
export const WORKSPACE = path.resolve(process.env.GG_WORKSPACE || process.cwd());
export function readWorkspaceFile(p, { maxBytes = 200000 } = {}) {
  const ws = fs.realpathSync(WORKSPACE);
  let real;
  try { real = fs.realpathSync(path.resolve(ws, String(p))); } catch { throw new Error(`${p}: no such file in the workspace (${ws})`); }
  if (real !== ws && !real.startsWith(ws + path.sep)) throw new Error(`${p} is outside the workspace (${ws}); set GG_WORKSPACE to allow another folder`);
  const st = fs.statSync(real);
  if (!st.isFile()) throw new Error(`${p} is not a file`);
  if (st.size > maxBytes) throw new Error(`${p} is larger than ${maxBytes} bytes`);
  return fs.readFileSync(real, "utf8");
}
