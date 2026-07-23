import path from 'path';
import { realpathSync } from 'fs';
import { timingSafeEqual } from 'crypto';

// Constant-time comparison of a caller-provided token against the expected secret.
// Returns false (never throws) on type/length mismatch so it is safe to call on
// untrusted request headers.
export function tokensMatch(provided, expected) {
  if (typeof provided !== 'string' || typeof expected !== 'string') return false;
  if (expected.length === 0) return false;
  const a = Buffer.from(provided, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  // Unequal lengths can't be timingSafeEqual'd; the length itself is not secret.
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

// Resolve a list of root directories to their canonical (symlink-free) absolute form.
// Roots that don't exist yet (e.g. a cache dir created lazily) are kept as absolute
// paths so they still match once created.
export function resolveAllowedDirs(dirs) {
  const out = [];
  for (const d of dirs || []) {
    if (!d) continue;
    const abs = path.resolve(d);
    let real = abs;
    try { real = realpathSync(abs); } catch { /* not created yet — use absolute path */ }
    out.push(real);
  }
  return out;
}

// Decide whether /send-media may read `filePath`. Resolves symlinks and confines the
// real path to an allow-listed root, with a hard deny-list that wins even if an
// operator configures an over-broad allowed dir. This closes the arbitrary local
// file read / exfil hole (CVE-2026-46555 class) against a LOWER-PRIVILEGED / sandboxed
// co-located process or a prompt-injected agent used as a confused deputy — it cannot
// point the bridge at session creds, .env, ~/.ssh, or patient data. It does NOT isolate
// a same-UID process (that can already read those files directly); see bridge.js.
//
// A single realpathSync() both resolves symlinks and detects non-existence (ENOENT),
// avoiding an existsSync()+realpathSync() check/use double-stat race.
//
// `allowedDirs` and `deniedDirs` should be pre-resolved with resolveAllowedDirs().
export function isPathAllowed(filePath, allowedDirs, deniedDirs = []) {
  if (typeof filePath !== 'string' || filePath.length === 0) {
    return { allowed: false, reason: 'empty path' };
  }
  let real;
  try {
    real = realpathSync(filePath);
  } catch (err) {
    if (err.code === 'ENOENT' || err.code === 'ENOTDIR') {
      return { allowed: false, reason: 'file not found' };
    }
    return { allowed: false, reason: `cannot resolve path: ${err.code || err.message}` };
  }

  const within = (root) => real === root || real.startsWith(root + path.sep);

  for (const denied of deniedDirs) {
    if (within(denied)) {
      return { allowed: false, reason: 'path is within a denied directory', realPath: real };
    }
  }
  for (const root of allowedDirs) {
    if (within(root)) {
      return { allowed: true, realPath: real };
    }
  }
  return { allowed: false, reason: 'path is outside the allowed media directories', realPath: real };
}

// Pure decision function for the bridge auth middleware, extracted so the auth gate
// (the actual security control) is unit-testable without spinning up express/Baileys.
// Returns null when the request is allowed to proceed, or { status, error } to reject.
// Fails closed: an unset bridgeToken rejects every non-open path with 503.
export function checkBridgeAuth(reqPath, headerToken, bridgeToken, openPaths) {
  if (openPaths && openPaths.has(reqPath)) return null;
  if (!bridgeToken) {
    return { status: 503, error: 'Bridge auth not configured. Set WHATSAPP_BRIDGE_TOKEN in the environment.' };
  }
  const provided = typeof headerToken === 'string' ? headerToken : '';
  if (!tokensMatch(provided, bridgeToken)) {
    return { status: 401, error: 'Invalid or missing bridge token' };
  }
  return null;
}
