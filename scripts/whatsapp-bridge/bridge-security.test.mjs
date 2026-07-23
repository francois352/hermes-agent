import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, symlinkSync } from 'node:fs';

import { tokensMatch, resolveAllowedDirs, isPathAllowed, checkBridgeAuth } from './bridge-security.js';

const OPEN = new Set(['/health']);

test('checkBridgeAuth: /health is open without a token', () => {
  assert.equal(checkBridgeAuth('/health', undefined, '', OPEN), null);
  assert.equal(checkBridgeAuth('/health', undefined, 's3cret', OPEN), null);
});

test('checkBridgeAuth: fails closed with 503 when the bridge token is unset', () => {
  const r = checkBridgeAuth('/send', 'anything', '', OPEN);
  assert.equal(r.status, 503);
  // Every non-open route is refused when unconfigured, even with a header present.
  assert.equal(checkBridgeAuth('/send-media', 's3cret', '', OPEN).status, 503);
});

test('checkBridgeAuth: 401 on missing or wrong token, null on exact match', () => {
  assert.equal(checkBridgeAuth('/send', undefined, 's3cret', OPEN).status, 401);   // missing
  assert.equal(checkBridgeAuth('/send', '', 's3cret', OPEN).status, 401);          // empty
  assert.equal(checkBridgeAuth('/send', 'wrong!', 's3cret', OPEN).status, 401);    // wrong
  assert.equal(checkBridgeAuth('/messages', 's3cret', 's3cret', OPEN), null);      // correct
  assert.equal(checkBridgeAuth('/send-media', 's3cret', 's3cret', OPEN), null);    // correct
});

test('checkBridgeAuth: a mangled path that is not exactly /health still requires a token', () => {
  // Path tricks can only make the gate MORE restrictive, never bypass it.
  assert.equal(checkBridgeAuth('/health/../send', 'anything', 's3cret', OPEN).status, 401);
});

test('tokensMatch requires an exact, non-empty match', () => {
  assert.equal(tokensMatch('s3cret', 's3cret'), true);
  assert.equal(tokensMatch('s3cret', 's3cre'), false);   // length differs
  assert.equal(tokensMatch('s3cret', 'wrong!'), false);  // same length, wrong value
  assert.equal(tokensMatch('', ''), false);              // empty expected never matches
  assert.equal(tokensMatch('anything', ''), false);
  assert.equal(tokensMatch(undefined, 's3cret'), false); // non-string provided
  assert.equal(tokensMatch(null, 's3cret'), false);
});

test('isPathAllowed permits files inside an allowed dir and rejects traversal outside it', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'hermes-wa-media-'));
  try {
    const mediaDir = path.join(root, 'cache');
    const secretsDir = path.join(root, 'secrets');
    mkdirSync(mediaDir);
    mkdirSync(secretsDir);

    const okFile = path.join(mediaDir, 'photo.jpg');
    const secretFile = path.join(secretsDir, 'creds.json');
    writeFileSync(okFile, 'jpeg');
    writeFileSync(secretFile, 'token');

    const allowed = resolveAllowedDirs([mediaDir]);

    assert.equal(isPathAllowed(okFile, allowed).allowed, true);

    // Directory traversal that escapes the allowed root must be rejected.
    const traversal = path.join(mediaDir, '..', 'secrets', 'creds.json');
    assert.equal(isPathAllowed(traversal, allowed).allowed, false);

    // A path directly outside the allowed root is rejected.
    assert.equal(isPathAllowed(secretFile, allowed).allowed, false);

    // Missing files report not-found, not allowed.
    const missing = isPathAllowed(path.join(mediaDir, 'nope.jpg'), allowed);
    assert.equal(missing.allowed, false);
    assert.equal(missing.reason, 'file not found');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('isPathAllowed follows symlinks so they cannot escape the allowed root', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'hermes-wa-symlink-'));
  try {
    const mediaDir = path.join(root, 'cache');
    const secretsDir = path.join(root, 'secrets');
    mkdirSync(mediaDir);
    mkdirSync(secretsDir);

    const secretFile = path.join(secretsDir, 'id_rsa');
    writeFileSync(secretFile, 'PRIVATE KEY');

    // A symlink *inside* the allowed dir pointing *outside* must not grant access.
    const evilLink = path.join(mediaDir, 'innocent.jpg');
    symlinkSync(secretFile, evilLink);

    const allowed = resolveAllowedDirs([mediaDir]);
    const verdict = isPathAllowed(evilLink, allowed);
    assert.equal(verdict.allowed, false, 'symlink escaping the allowed root must be denied');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('isPathAllowed denylist wins over an over-broad allowlist', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'hermes-wa-deny-'));
  try {
    const sessionDir = path.join(root, 'session');
    mkdirSync(sessionDir);
    const creds = path.join(sessionDir, 'creds.json');
    writeFileSync(creds, 'secret');

    // Operator misconfigures the allowlist to the whole root (which contains session/).
    const allowed = resolveAllowedDirs([root]);
    const denied = resolveAllowedDirs([sessionDir]);

    assert.equal(isPathAllowed(creds, allowed).allowed, true, 'sanity: allowed without denylist');
    assert.equal(isPathAllowed(creds, allowed, denied).allowed, false, 'denylist must override');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
