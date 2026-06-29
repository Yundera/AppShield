'use strict';

// Persistent file-backed adapter for oidc-provider.
//
// One instance per model name (oidc-provider calls `new Adapter(name)`).
// Documents live at  OAUTH_DATA_DIR/<Model>/<id>.json  as { payload, expiresAt }.
// Two sidecar index dirs provide the reverse lookups oidc-provider needs:
//   OAUTH_DATA_DIR/<Model>/_uid/<uid>.json       -> { id }     (findByUid: Session/Interaction)
//   OAUTH_DATA_DIR/<Model>/_userCode/<code>.json -> { id }     (findByUserCode: DeviceCode)
//   OAUTH_DATA_DIR/_grant/<grantId>.json         -> ["Model/id", ...]  (revokeByGrantId)
//
// Single node process => atomic temp-write + rename is enough; no cross-process locks.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_DIR = process.env.OAUTH_DATA_DIR || '/data/oauth';
const GRANT_DIR = path.join(DATA_DIR, '_grant');

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    return undefined;
  }
}

function writeJson(file, value) {
  ensureDir(path.dirname(file));
  const tmp = `${file}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(value));
  fs.renameSync(tmp, file);
}

function unlinkQuiet(file) {
  try {
    fs.unlinkSync(file);
  } catch (e) {
    /* already gone */
  }
}

// Sanitize an id/uid/userCode so it is safe as a single path segment.
function safe(name) {
  return encodeURIComponent(String(name));
}

class OAuthFileAdapter {
  constructor(name) {
    this.name = name;
    this.dir = path.join(DATA_DIR, name);
    this.uidDir = path.join(this.dir, '_uid');
    this.userCodeDir = path.join(this.dir, '_userCode');
    ensureDir(this.dir);
  }

  _docPath(id) {
    return path.join(this.dir, `${safe(id)}.json`);
  }

  async upsert(id, payload, expiresIn) {
    const expiresAt = expiresIn ? Date.now() + expiresIn * 1000 : undefined;
    writeJson(this._docPath(id), { payload, expiresAt });

    if (payload.uid) {
      writeJson(path.join(this.uidDir, `${safe(payload.uid)}.json`), { id });
    }
    if (payload.userCode) {
      writeJson(path.join(this.userCodeDir, `${safe(payload.userCode)}.json`), { id });
    }
    if (payload.grantId) {
      ensureDir(GRANT_DIR);
      const grantFile = path.join(GRANT_DIR, `${safe(payload.grantId)}.json`);
      const refs = readJson(grantFile) || [];
      const ref = `${this.name}/${id}`;
      if (!refs.includes(ref)) {
        refs.push(ref);
        writeJson(grantFile, refs);
      }
    }
  }

  async find(id) {
    const doc = readJson(this._docPath(id));
    if (!doc) return undefined;
    if (doc.expiresAt && doc.expiresAt < Date.now()) {
      await this.destroy(id);
      return undefined;
    }
    return doc.payload;
  }

  async findByUid(uid) {
    const idx = readJson(path.join(this.uidDir, `${safe(uid)}.json`));
    if (!idx) return undefined;
    return this.find(idx.id);
  }

  async findByUserCode(userCode) {
    const idx = readJson(path.join(this.userCodeDir, `${safe(userCode)}.json`));
    if (!idx) return undefined;
    return this.find(idx.id);
  }

  async consume(id) {
    const doc = readJson(this._docPath(id));
    if (!doc) return;
    doc.payload.consumed = Math.floor(Date.now() / 1000);
    writeJson(this._docPath(id), doc);
  }

  async destroy(id) {
    const doc = readJson(this._docPath(id));
    unlinkQuiet(this._docPath(id));
    if (doc && doc.payload) {
      if (doc.payload.uid) unlinkQuiet(path.join(this.uidDir, `${safe(doc.payload.uid)}.json`));
      if (doc.payload.userCode) {
        unlinkQuiet(path.join(this.userCodeDir, `${safe(doc.payload.userCode)}.json`));
      }
    }
  }

  async revokeByGrantId(grantId) {
    const grantFile = path.join(GRANT_DIR, `${safe(grantId)}.json`);
    const refs = readJson(grantFile);
    if (refs) {
      for (const ref of refs) {
        const sep = ref.indexOf('/');
        const model = ref.slice(0, sep);
        const id = ref.slice(sep + 1);
        // destroy via a sibling adapter for the referenced model
        await new OAuthFileAdapter(model).destroy(id);
      }
    }
    unlinkQuiet(grantFile);
  }
}

module.exports = OAuthFileAdapter;
