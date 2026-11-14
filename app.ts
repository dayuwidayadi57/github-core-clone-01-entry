// A one-process GitHub-compatible git forge: git smart HTTP (upload-pack v2,
// receive-pack v0), REST v3, GraphQL v4 and MCP over one in-memory store.
// Node 22 standard library only. No git binary, no outside service, no UI.
// Every timestamp and id the server emits comes from a deterministic counter,
// never from the wall clock, so two runs against one instance replay identically.

import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import { deflateSync, inflateSync } from 'node:zlib';

export const ZERO_OID = '0000000000000000000000000000000000000000';
const VIEWER_LOGIN = 'adaiversen';
const VIEWER_ID = 1000;
const VIEWER_NAME = 'ada iversen';
const VIEWER_EMAIL = 'adaiversen@example.invalid';
const FIXED_EPOCH = 1735689600;
const AGENT_STRING = 'forge/1.0.0';
const FORGE_NAME = 'forge';
const FORGE_VERSION = '1.0.0';
const UPLOAD_V0_CAPS =
  'multi_ack multi_ack_detailed side-band-64k thin-pack ofs-delta shallow agent=forge/1.0.0 symref=HEAD:refs/heads/main';
const RECEIVE_V0_CAPS =
  'report-status report-status-v2 side-band-64k delete-refs ofs-delta agent=forge/1.0.0 symref=HEAD:refs/heads/main';

// ---------------------------------------------------------------------------
// tiny deterministic counters (the only sources of time and ids in responses)
// ---------------------------------------------------------------------------

let clockSeq = 0;
let requestSeq = 0;
let nextDbId = 5000;

function nextIso(): string {
  const stamp = FIXED_EPOCH + clockSeq;
  clockSeq += 1;
  return new Date(stamp * 1000).toISOString();
}

function nextCommitEpoch(): number {
  const stamp = FIXED_EPOCH + 100000 + clockSeq;
  clockSeq += 1;
  return stamp;
}

function nextRequestId(): string {
  requestSeq += 1;
  return `req-${requestSeq}`;
}

// ---------------------------------------------------------------------------
// hashes, pkt-lines, pack varints
// ---------------------------------------------------------------------------

export function sha1Hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

export function hashObject(type: string, data: Buffer): string {
  const head = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return sha1Hex(Buffer.concat([head, data]));
}

function isObjectId(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{40}$/.test(value);
}

function pktLine(payload: Buffer | string): Buffer {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const size = body.length + 4;
  const head = Buffer.alloc(4);
  head.write(size.toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([head, body]);
}

const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

type PktKind = 'data' | 'flush' | 'delim' | 'end';
interface Pkt {
  kind: PktKind;
  payload: Buffer;
}

function encodePktLines(lines: Array<string | Buffer | 'flush' | 'delim'>): Buffer {
  const parts: Buffer[] = [];
  for (const line of lines) {
    if (line === 'flush') parts.push(PKT_FLUSH);
    else if (line === 'delim') parts.push(PKT_DELIM);
    else parts.push(pktLine(line));
  }
  return Buffer.concat(parts);
}

/** Parse pkt-lines; throws on a malformed frame instead of crashing the caller. */
function decodePktLines(buf: Buffer): Pkt[] {
  const out: Pkt[] = [];
  let at = 0;
  while (at < buf.length) {
    if (at + 4 > buf.length) throw new Error('truncated pkt-line header');
    const head = buf.subarray(at, at + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(head)) throw new Error('bad pkt-line length');
    const size = parseInt(head, 16);
    if (size === 0) {
      out.push({ kind: 'flush', payload: Buffer.alloc(0) });
      at += 4;
      continue;
    }
    if (size === 1) {
      out.push({ kind: 'delim', payload: Buffer.alloc(0) });
      at += 4;
      continue;
    }
    if (size === 2) {
      out.push({ kind: 'end', payload: Buffer.alloc(0) });
      at += 4;
      continue;
    }
    if (size < 4 || at + size > buf.length) throw new Error('pkt-line size out of range');
    out.push({ kind: 'data', payload: Buffer.from(buf.subarray(at + 4, at + size)) });
    at += size;
  }
  return out;
}

/** Inflate one zlib stream at `offset`; answers the bytes and the offset past it. */
function inflateAt(buffer: Buffer, offset: number): { data: Buffer; next: number } {
  const view = buffer.subarray(offset);
  let result: { buffer: Buffer; engine: { bytesWritten: number } };
  try {
    result = inflateSync(view, { info: true }) as unknown as { buffer: Buffer; engine: { bytesWritten: number } };
  } catch {
    throw new Error(`zlib stream at offset ${offset} did not inflate`);
  }
  const spent = result.engine.bytesWritten;
  if (!spent || spent <= 0) throw new Error(`zlib stream at offset ${offset} consumed no bytes`);
  return { data: result.buffer, next: offset + spent };
}

// ---------------------------------------------------------------------------
// git object primitives: trees, commits, tags, deltas
// ---------------------------------------------------------------------------

export type ObjectType = 'commit' | 'tree' | 'blob' | 'tag';

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function treeOrderKey(name: string, isDir: boolean): string {
  return isDir ? `${name}/` : name;
}

function compareTreeEntries(a: TreeEntry, b: TreeEntry): number {
  const ka = treeOrderKey(a.name, a.mode === '40000');
  const kb = treeOrderKey(b.name, b.mode === '40000');
  if (ka < kb) return -1;
  if (ka > kb) return 1;
  return 0;
}

export function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let at = 0;
  while (at < data.length) {
    const space = data.indexOf(0x20, at);
    if (space < 0) throw new Error('tree entry has no mode');
    const nul = data.indexOf(0, space + 1);
    if (nul < 0 || nul + 21 > data.length) throw new Error('tree entry is truncated');
    const mode = data.subarray(at, space).toString('ascii');
    const name = data.subarray(space + 1, nul).toString('utf8');
    const oid = Buffer.from(data.subarray(nul + 1, nul + 21)).toString('hex');
    entries.push({ mode, name, oid });
    at = nul + 21;
  }
  return entries;
}

export function buildTree(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort(compareTreeEntries);
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

interface CommitParts {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

export function parseCommit(data: Buffer): CommitParts {
  const text = data.toString('utf8');
  const blank = text.indexOf('\n\n');
  const head = blank < 0 ? text : text.slice(0, blank);
  const message = blank < 0 ? '' : text.slice(blank + 2);
  const out: CommitParts = { tree: '', parents: [], author: '', committer: '', message };
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) out.tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) out.parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) out.author = line.slice(7);
    else if (line.startsWith('committer ')) out.committer = line.slice(10);
  }
  return out;
}

export function buildCommit(parts: CommitParts): Buffer {
  const lines: string[] = [`tree ${parts.tree}`];
  for (const parent of parts.parents) lines.push(`parent ${parent}`);
  lines.push(`author ${parts.author}`);
  lines.push(`committer ${parts.committer}`);
  const message = parts.message.endsWith('\n') ? parts.message : `${parts.message}\n`;
  return Buffer.from(`${lines.join('\n')}\n\n${message}`, 'utf8');
}

interface TagParts {
  object: string;
  type: string;
  tag: string;
  tagger: string;
  message: string;
}

export function parseTag(data: Buffer): TagParts {
  const text = data.toString('utf8');
  const blank = text.indexOf('\n\n');
  const head = blank < 0 ? text : text.slice(0, blank);
  const message = blank < 0 ? '' : text.slice(blank + 2);
  const out: TagParts = { object: '', type: '', tag: '', tagger: '', message };
  for (const line of head.split('\n')) {
    if (line.startsWith('object ')) out.object = line.slice(7).trim();
    else if (line.startsWith('type ')) out.type = line.slice(5).trim();
    else if (line.startsWith('tag ')) out.tag = line.slice(4).trim();
    else if (line.startsWith('tagger ')) out.tagger = line.slice(7);
  }
  return out;
}

/** Apply a git delta's copy/insert stream to a base object's bytes. */
export function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let at = 0;
  const readSize = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      if (at >= delta.length) throw new Error('delta size varint is truncated');
      const byte = delta[at++];
      value += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if (!(byte & 0x80)) break;
      if (shift > 63) throw new Error('delta size varint is too long');
    }
    return value;
  };
  const sourceSize = readSize();
  const targetSize = readSize();
  if (sourceSize !== base.length) throw new Error('delta base size mismatch');
  const out = Buffer.allocUnsafe(targetSize);
  let written = 0;
  while (at < delta.length) {
    const op = delta[at++];
    if (op & 0x80) {
      let copyOffset = 0;
      let copySize = 0;
      let shift = 0;
      for (let bit = 0; bit < 4; bit += 1) {
        if (op & (1 << bit)) {
          if (at >= delta.length) throw new Error('delta copy offset is truncated');
          copyOffset += delta[at++] * 2 ** shift;
        }
        shift += 8;
      }
      shift = 0;
      for (let bit = 4; bit < 7; bit += 1) {
        if (op & (1 << bit)) {
          if (at >= delta.length) throw new Error('delta copy size is truncated');
          copySize += delta[at++] * 2 ** shift;
        }
        shift += 8;
      }
      if (copySize === 0) copySize = 0x10000;
      if (copyOffset + copySize > base.length) throw new Error('delta copy is out of range');
      if (written + copySize > targetSize) throw new Error('delta writes past its target');
      base.copy(out, written, copyOffset, copyOffset + copySize);
      written += copySize;
    } else if (op !== 0) {
      const literal = op & 0x7f;
      if (at + literal > delta.length) throw new Error('delta insert is truncated');
      if (written + literal > targetSize) throw new Error('delta writes past its target');
      delta.copy(out, written, at, at + literal);
      at += literal;
      written += literal;
    } else {
      throw new Error('delta opcode 0 is invalid');
    }
  }
  if (written !== targetSize) throw new Error('delta size mismatch');
  return out;
}

// ---------------------------------------------------------------------------
// packfiles: read (plain + OFS/REF deltas) and write (plain objects only)
// ---------------------------------------------------------------------------

export interface GitObject {
  type: ObjectType;
  data: Buffer;
}

const PACK_TYPE_CODES: Record<string, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const PACK_TYPES: Record<number, ObjectType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function packObjectHeader(typeCode: number, size: number): Buffer {
  const bytes: number[] = [];
  let first = (typeCode << 4) | (size & 0x0f);
  size >>= 4;
  if (size > 0) first |= 0x80;
  bytes.push(first);
  while (size > 0) {
    let next = size & 0x7f;
    size >>= 7;
    if (size > 0) next |= 0x80;
    bytes.push(next);
  }
  return Buffer.from(bytes);
}

/** Read a packfile; resolves deltas, recomputes every id, checks declared sizes. */
export function readPack(
  pack: Buffer,
  lookup: (oid: string) => GitObject | undefined,
): { objects: Map<string, GitObject>; deltaCount: number } {
  if (pack.length < 32) throw new Error('pack is too short');
  if (pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('pack does not start with PACK');
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const declaredCount = pack.readUInt32BE(8);
  const trailerStart = pack.length - 20;
  const trailer = pack.subarray(trailerStart).toString('hex');
  if (trailer !== sha1Hex(pack.subarray(0, trailerStart))) throw new Error('pack trailer does not match its bytes');

  interface Raw {
    offset: number;
    typeCode: number;
    size: number;
    data: Buffer;
    baseOffset?: number;
    baseOid?: string;
  }
  const raw: Raw[] = [];
  let at = 12;
  let deltaCount = 0;
  for (let index = 0; index < declaredCount; index += 1) {
    const start = at;
    if (at >= trailerStart) throw new Error('pack ends before its declared objects');
    let byte = pack[at++];
    const typeCode = (byte >> 4) & 0x07;
    let size = byte & 0x0f;
    let shift = 4;
    while (byte & 0x80) {
      if (at >= trailerStart) throw new Error('pack object header is truncated');
      byte = pack[at++];
      size |= (byte & 0x7f) << shift;
      shift += 7;
    }
    let baseOffset: number | undefined;
    let baseOid: string | undefined;
    if (typeCode === 6) {
      if (at >= trailerStart) throw new Error('ofs-delta has no base offset');
      byte = pack[at++];
      let value = byte & 0x7f;
      while (byte & 0x80) {
        if (at >= trailerStart) throw new Error('ofs-delta base offset is truncated');
        byte = pack[at++];
        value = ((value + 1) * 128) + (byte & 0x7f);
      }
      baseOffset = start - value;
      deltaCount += 1;
    } else if (typeCode === 7) {
      if (at + 20 > trailerStart) throw new Error('ref-delta has no base oid');
      baseOid = pack.subarray(at, at + 20).toString('hex');
      at += 20;
      deltaCount += 1;
    } else if (!(typeCode in PACK_TYPES)) {
      throw new Error(`pack object has unknown type code ${typeCode}`);
    }
    const inflated = inflateAt(pack, at);
    if (inflated.data.length !== size) throw new Error('pack object size mismatch');
    raw.push({ offset: start, typeCode, size, data: inflated.data, baseOffset, baseOid });
    at = inflated.next;
  }

  const byOffset = new Map<number, Raw>();
  for (const entry of raw) byOffset.set(entry.offset, entry);
  const resolved = new Map<string, GitObject>();
  const resolveOne = (entry: Raw, seen: Set<number>): GitObject => {
    const oid = hashObject(PACK_TYPES[entry.typeCode] ?? 'blob', entry.data);
    if (entry.typeCode === 6 || entry.typeCode === 7) {
      if (seen.has(entry.offset)) throw new Error('delta cycle in pack');
      seen.add(entry.offset);
      let base: GitObject | undefined;
      if (entry.baseOffset !== undefined) {
        const baseEntry = byOffset.get(entry.baseOffset);
        if (baseEntry === undefined) throw new Error('ofs-delta base is missing');
        base = resolveOne(baseEntry, seen);
      } else if (entry.baseOid !== undefined) {
        base = resolved.get(entry.baseOid) ?? lookup(entry.baseOid);
        if (base === undefined) throw new Error('ref-delta base is missing');
      }
      if (base === undefined) throw new Error('delta has no base');
      const data = applyDelta(base.data, entry.data);
      const object: GitObject = { type: base.type, data };
      const realOid = hashObject(object.type, object.data);
      resolved.set(realOid, object);
      return object;
    }
    const object: GitObject = { type: PACK_TYPES[entry.typeCode] as ObjectType, data: entry.data };
    resolved.set(oid, object);
    return object;
  };
  for (const entry of raw) resolveOne(entry, new Set());
  return { objects: resolved, deltaCount };
}

/** Write a packfile from plain objects, in deterministic oid order. */
export function writePack(objects: Map<string, GitObject>): Buffer {
  const oids = [...objects.keys()].sort();
  const parts: Buffer[] = [];
  const head = Buffer.alloc(12);
  head.write('PACK', 0, 'ascii');
  head.writeUInt32BE(2, 4);
  head.writeUInt32BE(oids.length, 8);
  parts.push(head);
  for (const oid of oids) {
    const object = objects.get(oid) as GitObject;
    const typeCode = PACK_TYPE_CODES[object.type] as number;
    parts.push(packObjectHeader(typeCode, object.data.length));
    parts.push(deflateSync(object.data));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, Buffer.from(sha1Hex(body), 'hex')]);
}

// ---------------------------------------------------------------------------
// reachability, generations, trees, history
// ---------------------------------------------------------------------------

export type ObjectStore = Map<string, GitObject>;

/** Everything reachable from `roots`: commits, their trees and parents, tags. */
export function collectReachable(store: ObjectStore, roots: Iterable<string>): Map<string, GitObject> {
  const out = new Map<string, GitObject>();
  const stack: string[] = [...roots];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (out.has(oid)) continue;
    const object = store.get(oid);
    if (object === undefined) continue;
    out.set(oid, object);
    if (object.type === 'commit') {
      const parts = parseCommit(object.data);
      stack.push(parts.tree);
      for (const parent of parts.parents) stack.push(parent);
    } else if (object.type === 'tag') {
      stack.push(parseTag(object.data).object);
    } else if (object.type === 'tree') {
      for (const entry of parseTree(object.data)) {
        if (entry.mode !== '160000') stack.push(entry.oid);
      }
    }
  }
  return out;
}

/** Generations of commits from `roots` (root = 0), following parent edges. */
export function commitGenerations(store: ObjectStore, roots: Iterable<string>): Map<string, number> {
  const gens = new Map<string, number>();
  const queue: Array<{ oid: string; gen: number }> = [];
  for (const root of roots) queue.push({ oid: root, gen: 0 });
  while (queue.length > 0) {
    const current = queue.shift() as { oid: string; gen: number };
    const known = gens.get(current.oid);
    if (known !== undefined && known <= current.gen) continue;
    const object = store.get(current.oid);
    if (object === undefined || object.type !== 'commit') continue;
    gens.set(current.oid, current.gen);
    for (const parent of parseCommit(object.data).parents) {
      queue.push({ oid: parent, gen: current.gen + 1 });
    }
  }
  return gens;
}

/** A commit's whole tree, flattened to path -> entry. */
export function flattenTree(store: ObjectStore, treeOid: string): Map<string, TreeEntry> {
  const out = new Map<string, TreeEntry>();
  const walk = (oid: string, prefix: string): void => {
    const object = store.get(oid);
    if (object === undefined || object.type !== 'tree') return;
    for (const entry of parseTree(object.data)) {
      const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
      if (entry.mode === '40000') walk(entry.oid, path);
      else out.set(path, entry);
    }
  };
  walk(treeOid, '');
  return out;
}

/**
 * Build nested trees from a flat path map, writing the trees into `into`
 * and answering the root tree oid.
 */
export function buildTreeFromFlat(
  flat: Map<string, TreeEntry>,
  into: ObjectStore,
): string {
  const buildLevel = (prefix: string): string => {
    const entries: TreeEntry[] = [];
    const subdirs = new Set<string>();
    for (const [path, entry] of flat) {
      if (prefix !== '' && !path.startsWith(`${prefix}/`)) continue;
      const rest = prefix === '' ? path : path.slice(prefix.length + 1);
      const slash = rest.indexOf('/');
      if (slash < 0) entries.push(entry);
      else subdirs.add(rest.slice(0, slash));
    }
    for (const dir of [...subdirs].sort()) {
      const childPrefix = prefix === '' ? dir : `${prefix}/${dir}`;
      const childOid = buildLevel(childPrefix);
      entries.push({ mode: '40000', name: dir, oid: childOid });
    }
    const data = buildTree(entries);
    const oid = hashObject('tree', data);
    into.set(oid, { type: 'tree', data });
    return oid;
  };
  return buildLevel('');
}

/** Newest-first history from a tip (parents in order, visited once). */
export function listCommits(store: ObjectStore, tip: string, limit: number): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const stack: string[] = [tip];
  while (stack.length > 0 && out.length < limit) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const object = store.get(oid);
    if (object === undefined || object.type !== 'commit') continue;
    out.push(oid);
    const parents = parseCommit(object.data).parents;
    for (let index = parents.length - 1; index >= 0; index -= 1) stack.push(parents[index]);
  }
  return out;
}

export function isAncestor(store: ObjectStore, maybeAncestor: string, oid: string): boolean {
  if (maybeAncestor === oid) return true;
  return commitGenerations(store, [oid]).has(maybeAncestor);
}

/** The nearest common ancestor of two commits, by summed generation. */
export function mergeBase(store: ObjectStore, a: string, b: string): string | null {
  if (a === b) return a;
  const gensA = commitGenerations(store, [a]);
  const gensB = commitGenerations(store, [b]);
  let best: string | null = null;
  let bestSum = Number.POSITIVE_INFINITY;
  for (const [oid, genA] of gensA) {
    const genB = gensB.get(oid);
    if (genB === undefined) continue;
    const sum = genA + genB;
    if (sum < bestSum) {
      bestSum = sum;
      best = oid;
    }
  }
  return best;
}

interface DiffLine {
  path: string;
  status: 'added' | 'modified' | 'deleted';
  oldOid: string | null;
  newOid: string | null;
  additions: number;
  deletions: number;
  changes: number;
}

function countLines(data: Buffer): string[] {
  const text = data.toString('utf8');
  if (text === '') return [];
  const lines = text.split('\n');
  if (lines[lines.length - 1] === '') lines.pop();
  return lines;
}

function lineDiff(oldData: Buffer | null, newData: Buffer | null): { additions: number; deletions: number } {
  if (oldData === null && newData === null) return { additions: 0, deletions: 0 };
  if (oldData === null) return { additions: countLines(newData as Buffer).length, deletions: 0 };
  if (newData === null) return { additions: 0, deletions: countLines(oldData).length };
  const oldLines = countLines(oldData);
  const newLines = countLines(newData);
  const oldCounts = new Map<string, number>();
  for (const line of oldLines) oldCounts.set(line, (oldCounts.get(line) ?? 0) + 1);
  let additions = 0;
  for (const line of newLines) {
    const left = oldCounts.get(line) ?? 0;
    if (left > 0) oldCounts.set(line, left - 1);
    else additions += 1;
  }
  let deletions = 0;
  for (const left of oldCounts.values()) deletions += left;
  return { additions, deletions };
}

/** Diff two trees (by root oid; null means an empty tree). */
export function diffTrees(
  store: ObjectStore,
  baseTreeOid: string | null,
  headTreeOid: string | null,
): DiffLine[] {
  const base = baseTreeOid === null ? new Map<string, TreeEntry>() : flattenTree(store, baseTreeOid);
  const head = headTreeOid === null ? new Map<string, TreeEntry>() : flattenTree(store, headTreeOid);
  const out: DiffLine[] = [];
  const paths = new Set([...base.keys(), ...head.keys()]);
  for (const path of [...paths].sort()) {
    const oldEntry = base.get(path) ?? null;
    const newEntry = head.get(path) ?? null;
    if (oldEntry !== null && newEntry !== null && oldEntry.oid === newEntry.oid) continue;
    const oldData = oldEntry === null ? null : (store.get(oldEntry.oid)?.data ?? null);
    const newData = newEntry === null ? null : (store.get(newEntry.oid)?.data ?? null);
    const counts = lineDiff(oldData, newData);
    const status = oldEntry === null ? 'added' : newEntry === null ? 'deleted' : 'modified';
    out.push({
      path,
      status,
      oldOid: oldEntry === null ? null : oldEntry.oid,
      newOid: newEntry === null ? null : newEntry.oid,
      additions: counts.additions,
      deletions: counts.deletions,
      changes: counts.additions + counts.deletions,
    });
  }
  return out;
}

/** Resolve a branch name, a full ref or a commit oid to its commit oid. */
export function resolveCommitTip(
  store: ObjectStore,
  refs: Map<string, string>,
  refOrBranchOrOid: string,
): string | null {
  let oid: string | undefined;
  if (refs.has(refOrBranchOrOid)) oid = refs.get(refOrBranchOrOid);
  else if (refs.has(`refs/heads/${refOrBranchOrOid}`)) oid = refs.get(`refs/heads/${refOrBranchOrOid}`);
  else if (isObjectId(refOrBranchOrOid)) oid = refOrBranchOrOid;
  else return null;
  if (oid === undefined) return null;
  const object = store.get(oid);
  if (object === undefined) return null;
  if (object.type === 'commit') return oid;
  if (object.type === 'tag') {
    const target = parseTag(object.data).object;
    const targetObject = store.get(target);
    return targetObject !== undefined && targetObject.type === 'commit' ? target : null;
  }
  return null;
}

/** Look a path up under a commit tip: a file, a directory, or nothing. */
export function lookupPath(
  store: ObjectStore,
  tip: string,
  path: string,
): { kind: 'file'; oid: string } | { kind: 'dir'; treeOid: string; flat: Map<string, TreeEntry> } | null {
  const commit = store.get(tip);
  if (commit === undefined || commit.type !== 'commit') return null;
  const rootTree = parseCommit(commit.data).tree;
  if (path === '') {
    return { kind: 'dir', treeOid: rootTree, flat: flattenTree(store, rootTree) };
  }
  const flat = flattenTree(store, rootTree);
  const file = flat.get(path);
  if (file !== undefined) return { kind: 'file', oid: file.oid };
  const prefix = `${path}/`;
  const under = new Map<string, TreeEntry>();
  for (const [candidate, entry] of flat) {
    if (candidate.startsWith(prefix)) under.set(candidate.slice(prefix.length), entry);
  }
  if (under.size === 0) return null;
  const treeOid = buildTreeFromFlat(under, new Map());
  return { kind: 'dir', treeOid, flat: under };
}

// ---------------------------------------------------------------------------
// the store: repositories, issues, pull requests, one shared number counter
// ---------------------------------------------------------------------------

export interface Issue {
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  createdAt: string;
  updatedAt: string;
  closedAt: string | null;
  comments: Array<{ id: number; body: string; createdAt: string }>;
}

export interface PullRequest {
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  head: string;
  base: string;
  headSha: string;
  baseSha: string;
  createdAt: string;
  updatedAt: string;
}

export interface Repo {
  name: string;
  owner: string;
  description: string;
  isPrivate: boolean;
  defaultBranch: string;
  databaseId: number;
  createdAt: string;
  updatedAt: string;
  objects: ObjectStore;
  refs: Map<string, string>;
  labels: Map<string, { name: string; color: string }>;
  issues: Map<number, Issue>;
  pulls: Map<number, PullRequest>;
  nextNumber: number;
  nextCommentId: number;
}

const repos = new Map<string, Repo>();

function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}

function createRepoRecord(name: string, description: string, isPrivate: boolean, defaultBranch: string): Repo {
  const now = nextIso();
  const repo: Repo = {
    name,
    owner: VIEWER_LOGIN,
    description,
    isPrivate,
    defaultBranch: defaultBranch === '' ? 'main' : defaultBranch,
    databaseId: nextDbId++,
    createdAt: now,
    updatedAt: now,
    objects: new Map(),
    refs: new Map(),
    labels: new Map(),
    issues: new Map(),
    pulls: new Map(),
    nextNumber: 1,
    nextCommentId: 1,
  };
  return repo;
}

function globalId(kind: string, dbid: number, num?: number): string {
  const text = num === undefined ? `${kind}:${dbid}` : `${kind}:${dbid}:${num}`;
  return Buffer.from(text, 'utf8').toString('base64');
}

function parseGlobalId(id: string): { kind: string; dbid: number; num?: number } | null {
  try {
    const text = Buffer.from(id, 'base64').toString('utf8');
    const parts = text.split(':');
    if (parts.length < 2 || parts.length > 3) return null;
    const dbid = Number(parts[1]);
    if (!Number.isInteger(dbid) || dbid <= 0) return null;
    if (parts.length === 3) {
      const num = Number(parts[2]);
      if (!Number.isInteger(num) || num <= 0) return null;
      return { kind: parts[0], dbid, num };
    }
    return { kind: parts[0], dbid };
  } catch {
    return null;
  }
}

function repoByGlobalId(id: string): Repo | null {
  const parsed = parseGlobalId(id);
  if (parsed === null || parsed.kind !== 'Repository') return null;
  for (const repo of repos.values()) {
    if (repo.databaseId === parsed.dbid) return repo;
  }
  return null;
}

function repoJson(repo: Repo): Record<string, unknown> {
  return {
    id: repo.databaseId,
    node_id: globalId('Repository', repo.databaseId),
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner, id: VIEWER_ID },
    private: repo.isPrivate,
    description: repo.description,
    default_branch: repo.defaultBranch,
    created_at: repo.createdAt,
    updated_at: repo.updatedAt,
    html_url: `https://github.com/${repo.owner}/${repo.name}`,
    clone_url: `https://github.com/${repo.owner}/${repo.name}.git`,
    has_issues: true,
  };
}

function issueJson(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: repo.databaseId * 100000 + issue.number,
    node_id: globalId('Issue', repo.databaseId, issue.number),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((name) => {
      const label = repo.labels.get(name);
      return { name, color: label === undefined ? 'ededed' : label.color };
    }),
    created_at: issue.createdAt,
    updated_at: issue.updatedAt,
    closed_at: issue.closedAt,
    user: { login: VIEWER_LOGIN, id: VIEWER_ID },
  };
}

function pullJson(repo: Repo, pull: PullRequest): Record<string, unknown> {
  return {
    id: repo.databaseId * 100000 + pull.number,
    node_id: globalId('PullRequest', repo.databaseId, pull.number),
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    head: { ref: pull.head, sha: pull.headSha, label: `${repo.owner}:${pull.head}` },
    base: { ref: pull.base, sha: pull.baseSha, label: `${repo.owner}:${pull.base}` },
    created_at: pull.createdAt,
    updated_at: pull.updatedAt,
    user: { login: VIEWER_LOGIN, id: VIEWER_ID },
  };
}

function identityLine(): string {
  return `${VIEWER_NAME} <${VIEWER_EMAIL}> ${nextCommitEpoch()} +0000`;
}

/**
 * Apply one file write (or delete, when content is null) on a branch:
 * a new blob, a rebuilt tree, a new commit, the ref moved. A branch that
 * does not exist starts from the default branch's tip.
 */
export function commitFileChange(
  repo: Repo,
  branch: string,
  path: string,
  content: Buffer | null,
  message: string,
): { commitSha: string; blobSha: string | null } {
  const defaultTip = resolveCommitTip(repo.objects, repo.refs, repo.defaultBranch);
  let tip = resolveCommitTip(repo.objects, repo.refs, branch);
  if (tip === null && branch !== repo.defaultBranch) tip = defaultTip;
  const baseTree = tip === null ? null : parseCommit((repo.objects.get(tip) as GitObject).data).tree;
  const flat = baseTree === null ? new Map<string, TreeEntry>() : flattenTree(repo.objects, baseTree);
  let blobSha: string | null = null;
  if (content === null) {
    flat.delete(path);
  } else {
    blobSha = hashObject('blob', content);
    repo.objects.set(blobSha, { type: 'blob', data: content });
    flat.set(path, { mode: '100644', name: path.split('/').pop() as string, oid: blobSha });
  }
  const treeOid = buildTreeFromFlat(flat, repo.objects);
  const commit = buildCommit({
    tree: treeOid,
    parents: tip === null ? [] : [tip],
    author: identityLine(),
    committer: identityLine(),
    message,
  });
  const commitSha = hashObject('commit', commit);
  repo.objects.set(commitSha, { type: 'commit', data: commit });
  repo.refs.set(`refs/heads/${branch}`, commitSha);
  return { commitSha, blobSha };
}

/** The changed files of a pull request: merge-base tree vs head tip tree. */
export function prFiles(repo: Repo, pull: PullRequest): DiffLine[] {
  const baseTip = resolveCommitTip(repo.objects, repo.refs, pull.base);
  const headTip = resolveCommitTip(repo.objects, repo.refs, pull.head);
  if (headTip === null) return [];
  const base = baseTip === null ? null : mergeBase(repo.objects, baseTip, headTip);
  const baseTree = base === null ? null : parseCommit((repo.objects.get(base) as GitObject).data).tree;
  const headTree = parseCommit((repo.objects.get(headTip) as GitObject).data).tree;
  return diffTrees(repo.objects, baseTree, headTree);
}

/** Whether the head and the base both changed a path differently since the base. */
export function prConflicts(repo: Repo, pull: PullRequest): boolean {
  const baseTip = resolveCommitTip(repo.objects, repo.refs, pull.base);
  const headTip = resolveCommitTip(repo.objects, repo.refs, pull.head);
  if (baseTip === null || headTip === null) return false;
  const base = mergeBase(repo.objects, baseTip, headTip);
  if (base === null) return false;
  const baseTree = parseCommit((repo.objects.get(base) as GitObject).data).tree;
  const baseTipTree = parseCommit((repo.objects.get(baseTip) as GitObject).data).tree;
  const headTree = parseCommit((repo.objects.get(headTip) as GitObject).data).tree;
  const baseSide = diffTrees(repo.objects, baseTree, baseTipTree);
  const headSide = diffTrees(repo.objects, baseTree, headTree);
  const baseChanged = new Map(baseSide.map((line) => [line.path, line]));
  for (const line of headSide) {
    const other = baseChanged.get(line.path);
    if (other === undefined) continue;
    if (other.newOid !== line.newOid) return true;
  }
  return false;
}

/** Squash-merge a pull request onto its base branch; answers the merge sha. */
export function squashMerge(repo: Repo, pull: PullRequest): string {
  const headTip = resolveCommitTip(repo.objects, repo.refs, pull.head) as string;
  const baseTip = resolveCommitTip(repo.objects, repo.refs, pull.base) as string;
  const headTree = parseCommit((repo.objects.get(headTip) as GitObject).data).tree;
  const message = `Merge pull request #${pull.number} from ${repo.owner}/${pull.head}`;
  const commit = buildCommit({
    tree: headTree,
    parents: [baseTip],
    author: identityLine(),
    committer: identityLine(),
    message,
  });
  const commitSha = hashObject('commit', commit);
  repo.objects.set(commitSha, { type: 'commit', data: commit });
  repo.refs.set(`refs/heads/${pull.base}`, commitSha);
  pull.merged = true;
  pull.mergedAt = nextIso();
  pull.mergeCommitSha = commitSha;
  pull.state = 'closed';
  pull.updatedAt = nextIso();
  pull.baseSha = commitSha;
  return commitSha;
}

function mergeableState(repo: Repo, pull: PullRequest): 'MERGEABLE' | 'CONFLICTING' | 'UNKNOWN' {
  const headTip = resolveCommitTip(repo.objects, repo.refs, pull.head);
  const baseTip = resolveCommitTip(repo.objects, repo.refs, pull.base);
  if (headTip === null || baseTip === null) return 'UNKNOWN';
  return prConflicts(repo, pull) ? 'CONFLICTING' : 'MERGEABLE';
}

// ---------------------------------------------------------------------------
// HTTP plumbing: bodies, answers, auth
// ---------------------------------------------------------------------------

const JSON_TYPE = 'application/json';

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > 64 * 1024 * 1024) {
        reject(new Error('request body is too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function sendJson(res: ServerResponse, status: number, body: unknown, extra?: Record<string, string>): void {
  const text = JSON.stringify(body);
  const headers: Record<string, string> = {
    'content-type': JSON_TYPE,
    'x-github-request-id': nextRequestId(),
    ...extra,
  };
  res.writeHead(status, headers);
  res.end(text);
}

function sendBytes(res: ServerResponse, status: number, body: Buffer, contentType: string): void {
  res.writeHead(status, { 'content-type': contentType, 'content-length': body.length });
  res.end(body);
}

function errorJson(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}

function expectedToken(): string | null {
  const token = process.env.MAKEFUN_SHOP_TOKEN;
  return token === undefined || token === '' ? null : token;
}

function checkAuth(req: IncomingMessage): boolean {
  const header = req.headers.authorization;
  if (header === undefined || !header.startsWith('Bearer ')) return false;
  const token = header.slice('Bearer '.length);
  if (token === '') return false;
  const wanted = expectedToken();
  if (wanted === null) return true;
  return token === wanted;
}

function parseJsonBody(text: Buffer): unknown | null {
  if (text.length === 0) return null;
  try {
    return JSON.parse(text.toString('utf8')) as unknown;
  } catch {
    return undefined;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function decodePath(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function splitPath(raw: string): string[] {
  const clean = raw.split('?')[0];
  const trimmed = clean.replace(/\/+$/, '');
  return trimmed.split('/').filter((part) => part !== '').map(decodePath);
}

// ---------------------------------------------------------------------------
// git smart HTTP: /<owner>/<repo>.git/info/refs, /git-upload-pack, /git-receive-pack
// ---------------------------------------------------------------------------

function sortedRefNames(repo: Repo): string[] {
  return [...repo.refs.keys()].sort();
}

function tagTargetOid(repo: Repo, oid: string): string | null {
  const object = repo.objects.get(oid);
  if (object === undefined || object.type !== 'tag') return null;
  return parseTag(object.data).object;
}

/** A v0 ref advertisement: the service line, the flush, then the ref lines. */
function v0Advertisement(repo: Repo, service: string, caps: string): Buffer {
  const lines: Array<string | Buffer | 'flush'> = [`# service=${service}\n`, 'flush'];
  const names = sortedRefNames(repo);
  if (names.length === 0) {
    lines.push(`${ZERO_OID} capabilities^{}\0${caps}\n`);
  } else {
    const defaultTip = repo.refs.get(`refs/heads/${repo.defaultBranch}`) ?? ZERO_OID;
    lines.push(`${defaultTip} HEAD\0${caps}\n`);
    for (const name of names) {
      const oid = repo.refs.get(name) as string;
      lines.push(`${oid} ${name}\n`);
      const peeled = tagTargetOid(repo, oid);
      if (peeled !== null) lines.push(`${peeled} ${name}^{}\n`);
    }
  }
  lines.push('flush');
  return encodePktLines(lines);
}

/** The v2 capability advertisement for upload-pack. */
function v2Advertisement(): Buffer {
  return encodePktLines([
    '# service=git-upload-pack\n',
    'flush',
    'version 2\n',
    `agent=${AGENT_STRING}\n`,
    'ls-refs=unborn\n',
    'fetch=shallow filter\n',
    'object-format=sha1\n',
    'flush',
  ]);
}

function findRepo(owner: string, name: string): Repo | null {
  if (owner !== VIEWER_LOGIN) return null;
  return repos.get(repoKey(owner, name)) ?? null;
}

function handleInfoRefs(req: IncomingMessage, res: ServerResponse, owner: string, name: string, service: string): void {
  const repo = findRepo(owner, name);
  if (repo === null) {
    errorJson(res, 404, 'repository not found');
    return;
  }
  if (service === 'git-upload-pack') {
    const version = (req.headers['git-protocol'] ?? '') === 'version=2' ? 2 : 0;
    if (version === 2) {
      sendBytes(res, 200, v2Advertisement(), 'application/x-git-upload-pack-advertisement');
    } else {
      sendBytes(res, 200, v0Advertisement(repo, service, UPLOAD_V0_CAPS), 'application/x-git-upload-pack-advertisement');
    }
    return;
  }
  if (service === 'git-receive-pack') {
    sendBytes(res, 200, v0Advertisement(repo, service, RECEIVE_V0_CAPS), 'application/x-git-receive-pack-advertisement');
    return;
  }
  errorJson(res, 404, 'unknown service');
}

/** Split one v2 argument line on its first space, else its first `=`. */
function splitV2Arg(line: string): { key: string; value: string | null } {
  const space = line.indexOf(' ');
  if (space >= 0) return { key: line.slice(0, space), value: line.slice(space + 1) };
  const equals = line.indexOf('=');
  if (equals >= 0) return { key: line.slice(0, equals), value: line.slice(equals + 1) };
  return { key: line, value: null };
}

interface V2Request {
  command: string;
  args: Array<{ key: string; value: string | null }>;
}

function parseV2Request(body: Buffer): V2Request {
  const packets = decodePktLines(body);
  const commandLine = packets.find((packet) => packet.kind === 'data');
  if (commandLine === undefined) throw new Error('no command line');
  const first = splitV2Arg(commandLine.payload.toString('utf8').replace(/\n$/, ''));
  if (first.key !== 'command' || first.value === null) throw new Error('first line is not a command');
  const args: Array<{ key: string; value: string | null }> = [];
  let pastDelim = false;
  for (const packet of packets) {
    if (packet.kind === 'delim') {
      pastDelim = true;
      continue;
    }
    if (packet.kind !== 'data') continue;
    if (!pastDelim) continue;
    const text = packet.payload.toString('utf8').replace(/\n$/, '');
    if (text === '') continue;
    args.push(splitV2Arg(text));
  }
  return { command: first.value, args };
}

function handleLsRefs(repo: Repo, args: Array<{ key: string; value: string | null }>): Buffer {
  const wantPeel = args.some((arg) => arg.key === 'peel');
  const wantSymrefs = args.some((arg) => arg.key === 'symrefs');
  const wantUnborn = args.some((arg) => arg.key === 'unborn');
  const prefixes = args.filter((arg) => arg.key === 'ref-prefix').map((arg) => arg.value ?? '');
  const keep = (name: string): boolean => prefixes.length === 0 || prefixes.some((prefix) => name.startsWith(prefix));
  const lines: string[] = [];
  const names = sortedRefNames(repo);
  if (names.length === 0) {
    if (wantUnborn && keep('HEAD')) lines.push('unborn HEAD symref-target:refs/heads/main');
  } else {
    const defaultTip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
    if (defaultTip !== undefined && keep('HEAD')) {
      const symref = wantSymrefs ? ` symref-target:refs/heads/${repo.defaultBranch}` : '';
      lines.push(`${defaultTip} HEAD${symref}`);
    }
    for (const name of names) {
      if (!keep(name)) continue;
      const oid = repo.refs.get(name) as string;
      let line = `${oid} ${name}`;
      if (wantPeel) {
        const peeled = tagTargetOid(repo, oid);
        if (peeled !== null) line += ` peeled:${peeled}`;
      }
      lines.push(line);
    }
  }
  const parts: Buffer[] = [];
  for (const line of lines) parts.push(pktLine(`${line}\n`));
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

interface FetchSelection {
  send: Map<string, GitObject>;
  shallowOut: string[];
  unshallowOut: string[];
}

// The objects a fetch must send for a set of commits: each commit plus its tree
// and blobs, but NEVER the commits' parents. Following parents here would defeat
// a shallow depth limit (the whole history would ride along in the pack).
function collectTreeClosure(store: ObjectStore, commitOids: Iterable<string>): Map<string, GitObject> {
  const out = new Map<string, GitObject>();
  const stack: string[] = [];
  for (const oid of commitOids) {
    const object = store.get(oid);
    if (object === undefined) continue;
    out.set(oid, object);
    if (object.type === 'commit') stack.push(parseCommit(object.data).tree);
    else if (object.type === 'tag') stack.push(parseTag(object.data).object);
  }
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (out.has(oid)) continue;
    const object = store.get(oid);
    if (object === undefined) continue;
    out.set(oid, object);
    if (object.type === 'tree') {
      for (const entry of parseTree(object.data)) {
        if (entry.mode !== '160000') stack.push(entry.oid);
      }
    } else if (object.type === 'tag') {
      stack.push(parseTag(object.data).object);
    }
  }
  return out;
}

function fetchSelection(
  repo: Repo,
  wants: string[],
  haves: string[],
  knownShallow: string[],
  depth: number | null,
): FetchSelection {
  const store = repo.objects;
  const maxGen = depth === null ? Number.POSITIVE_INFINITY : depth;
  const included = new Map<string, number>();
  const queue: Array<{ oid: string; gen: number }> = [];
  const wantTags: string[] = [];
  for (const want of wants) {
    const object = store.get(want);
    if (object === undefined) continue;
    if (object.type === 'tag') {
      wantTags.push(want);
      const target = parseTag(object.data).object;
      const targetObject = store.get(target);
      if (targetObject !== undefined && targetObject.type === 'commit') queue.push({ oid: target, gen: 0 });
    } else if (object.type === 'commit') {
      queue.push({ oid: want, gen: 0 });
    }
  }
  while (queue.length > 0) {
    const current = queue.shift() as { oid: string; gen: number };
    if (current.gen >= maxGen) continue;
    const known = included.get(current.oid);
    if (known !== undefined && known <= current.gen) continue;
    included.set(current.oid, current.gen);
    const object = store.get(current.oid);
    if (object === undefined || object.type !== 'commit') continue;
    for (const parent of parseCommit(object.data).parents) {
      queue.push({ oid: parent, gen: current.gen + 1 });
    }
  }
  const shallowSet = new Set(knownShallow);
  const haveClosure = new Map<string, GitObject>();
  const haveQueue: string[] = [...haves];
  while (haveQueue.length > 0) {
    const oid = haveQueue.pop() as string;
    if (haveClosure.has(oid)) continue;
    const object = store.get(oid);
    if (object === undefined) continue;
    if (object.type === 'commit') {
      const parts = parseCommit(object.data);
      haveClosure.set(oid, object);
      const treeClosure = collectReachable(store, [parts.tree]);
      for (const [key, value] of treeClosure) haveClosure.set(key, value);
      if (!shallowSet.has(oid)) {
        for (const parent of parts.parents) haveQueue.push(parent);
      }
    } else if (object.type === 'tag') {
      haveClosure.set(oid, object);
      haveQueue.push(parseTag(object.data).object);
    } else {
      haveClosure.set(oid, object);
    }
  }
  const wanted = new Map<string, GitObject>();
  for (const tag of wantTags) {
    const object = store.get(tag);
    if (object !== undefined) wanted.set(tag, object);
  }
  const roots: string[] = [...included.keys()];
  const closure = collectTreeClosure(store, roots);
  for (const [oid, object] of closure) wanted.set(oid, object);
  const send = new Map<string, GitObject>();
  for (const [oid, object] of wanted) {
    if (!haveClosure.has(oid)) send.set(oid, object);
  }
  let shallowOut: string[] = [];
  if (depth !== null) {
    shallowOut = [...included.entries()].filter(([, gen]) => gen === depth - 1).map(([oid]) => oid);
  }
  const unshallowOut = knownShallow.filter((oid) => included.has(oid));
  return { send, shallowOut, unshallowOut };
}

function sidebandPack(pack: Buffer): Buffer {
  const parts: Buffer[] = [];
  const chunkSize = 32768;
  for (let at = 0; at < pack.length; at += chunkSize) {
    const chunk = pack.subarray(at, Math.min(pack.length, at + chunkSize));
    parts.push(pktLine(Buffer.concat([Buffer.from([1]), chunk])));
  }
  return Buffer.concat(parts);
}

function handleFetchV2(repo: Repo, args: Array<{ key: string; value: string | null }>): Buffer {
  const wants = args.filter((arg) => arg.key === 'want').map((arg) => arg.value ?? '');
  const haves = args.filter((arg) => arg.key === 'have').map((arg) => arg.value ?? '');
  const shallow = args.filter((arg) => arg.key === 'shallow').map((arg) => arg.value ?? '');
  const deepenArg = args.find((arg) => arg.key === 'deepen');
  const depth = deepenArg !== undefined && deepenArg.value !== null ? parseInt(deepenArg.value, 10) : null;
  const selection = fetchSelection(repo, wants, haves, shallow, Number.isFinite(depth) ? depth : null);
  const parts: Buffer[] = [];
  parts.push(pktLine('acknowledgments\n'));
  if (selection.send.size === 0) {
    for (const want of wants) {
      if (repo.objects.has(want)) parts.push(pktLine(`ACK ${want}\n`));
    }
    parts.push(pktLine('ready\n'));
  } else {
    parts.push(pktLine('NAK\n'));
    parts.push(pktLine('ready\n'));
  }
  parts.push(PKT_DELIM);
  if (selection.shallowOut.length > 0 || selection.unshallowOut.length > 0) {
    parts.push(pktLine('shallow-info\n'));
    for (const oid of selection.shallowOut) parts.push(pktLine(`shallow ${oid}\n`));
    for (const oid of selection.unshallowOut) parts.push(pktLine(`unshallow ${oid}\n`));
    parts.push(PKT_DELIM);
  }
  if (selection.send.size > 0) {
    parts.push(pktLine('packfile\n'));
    parts.push(sidebandPack(writePack(selection.send)));
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

function handleFetchV0(repo: Repo, body: Buffer): Buffer {
  const packets = decodePktLines(body);
  const wants: string[] = [];
  const haves: string[] = [];
  const shallow: string[] = [];
  let depth: number | null = null;
  let inSecondSection = false;
  for (const packet of packets) {
    if (packet.kind === 'flush') {
      inSecondSection = true;
      continue;
    }
    if (packet.kind !== 'data') continue;
    const text = packet.payload.toString('utf8').replace(/\n$/, '');
    if (text.startsWith('want ')) wants.push(text.slice(5).trim());
    else if (text.startsWith('have ')) haves.push(text.slice(5).trim());
    else if (text.startsWith('shallow ')) shallow.push(text.slice(8).trim());
    else if (text.startsWith('deepen ')) depth = parseInt(text.slice(7).trim(), 10);
  }
  void inSecondSection;
  const selection = fetchSelection(repo, wants, haves, shallow, Number.isFinite(depth) ? depth : null);
  const parts: Buffer[] = [];
  if (selection.send.size === 0) {
    for (const want of wants) {
      if (repo.objects.has(want)) parts.push(pktLine(`ACK ${want}\n`));
    }
  } else {
    parts.push(pktLine('NAK\n'));
  }
  for (const oid of selection.shallowOut) parts.push(pktLine(`shallow ${oid}\n`));
  for (const oid of selection.unshallowOut) parts.push(pktLine(`unshallow ${oid}\n`));
  if (selection.send.size > 0) parts.push(sidebandPack(writePack(selection.send)));
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

async function handleUploadPack(req: IncomingMessage, res: ServerResponse, repo: Repo): Promise<void> {
  const body = await readBody(req);
  const isV2 = (req.headers['git-protocol'] ?? '') === 'version=2';
  try {
    if (isV2) {
      const request = parseV2Request(body);
      if (request.command === 'ls-refs') {
        sendBytes(res, 200, handleLsRefs(repo, request.args), 'application/x-git-upload-pack-result');
        return;
      }
      if (request.command === 'fetch') {
        sendBytes(res, 200, handleFetchV2(repo, request.args), 'application/x-git-upload-pack-result');
        return;
      }
      errorJson(res, 400, `unknown command ${request.command}`);
      return;
    }
    sendBytes(res, 200, handleFetchV0(repo, body), 'application/x-git-upload-pack-result');
  } catch (err) {
    errorJson(res, 400, err instanceof Error ? err.message : 'bad request');
  }
}

interface PushCommand {
  oldOid: string;
  newOid: string;
  ref: string;
}

async function handleReceivePack(req: IncomingMessage, res: ServerResponse, repo: Repo): Promise<void> {
  const body = await readBody(req);
  let commands: PushCommand[] = [];
  let packOffset = 0;
  try {
    let at = 0;
    let seenFlush = false;
    while (at < body.length) {
      if (at + 4 > body.length) throw new Error('truncated pkt-line header');
      const head = body.subarray(at, at + 4).toString('ascii');
      if (!/^[0-9a-fA-F]{4}$/.test(head)) throw new Error('bad pkt-line length');
      const size = parseInt(head, 16);
      if (size === 0) {
        seenFlush = true;
        packOffset = at + 4;
        break;
      }
      if (size < 4 || at + size > body.length) throw new Error('pkt-line size out of range');
      const payload = body.subarray(at + 4, at + size);
      const text = payload.toString('utf8').replace(/\n$/, '');
      const nul = text.indexOf('\0');
      const commandText = nul >= 0 ? text.slice(0, nul) : text;
      const parts = commandText.split(' ');
      if (parts.length < 3) throw new Error('bad push command line');
      commands.push({ oldOid: parts[0], newOid: parts[1], ref: parts[2] });
      at += size;
    }
    if (!seenFlush) throw new Error('push has no command flush');
  } catch (err) {
    errorJson(res, 400, err instanceof Error ? err.message : 'bad push body');
    return;
  }
  const updatesRef = commands.some((command) => command.newOid !== ZERO_OID);
  const packBytes = body.subarray(packOffset);
  let unpackOk = true;
  let unpackDetail = 'ok';
  if (updatesRef) {
    try {
      const read = readPack(packBytes, (oid) => repo.objects.get(oid));
      for (const [oid, object] of read.objects) repo.objects.set(oid, object);
    } catch (err) {
      unpackOk = false;
      unpackDetail = err instanceof Error ? err.message : 'unpack failed';
    }
  }
  const results: Array<{ ref: string; ok: boolean; reason: string }> = [];
  if (unpackOk) {
    for (const command of commands) {
      const current = repo.refs.get(command.ref);
      if (command.newOid === ZERO_OID) {
        if (current === undefined) {
          results.push({ ref: command.ref, ok: false, reason: 'ref does not exist' });
        } else if (command.oldOid !== ZERO_OID && command.oldOid !== current) {
          results.push({ ref: command.ref, ok: false, reason: 'old oid does not match' });
        } else {
          repo.refs.delete(command.ref);
          results.push({ ref: command.ref, ok: true, reason: '' });
        }
        continue;
      }
      if (!repo.objects.has(command.newOid)) {
        results.push({ ref: command.ref, ok: false, reason: 'object does not exist' });
        continue;
      }
      if (command.oldOid === ZERO_OID) {
        if (current !== undefined) {
          results.push({ ref: command.ref, ok: false, reason: 'ref already exists' });
        } else {
          repo.refs.set(command.ref, command.newOid);
          results.push({ ref: command.ref, ok: true, reason: '' });
        }
        continue;
      }
      if (current === undefined) {
        results.push({ ref: command.ref, ok: false, reason: 'ref does not exist' });
        continue;
      }
      if (command.oldOid !== current) {
        results.push({ ref: command.ref, ok: false, reason: 'old oid does not match' });
        continue;
      }
      if (command.ref.startsWith('refs/heads/') && !isAncestor(repo.objects, command.oldOid, command.newOid)) {
        results.push({ ref: command.ref, ok: false, reason: 'non-fast-forward' });
        continue;
      }
      repo.refs.set(command.ref, command.newOid);
      results.push({ ref: command.ref, ok: true, reason: '' });
    }
  } else {
    for (const command of commands) results.push({ ref: command.ref, ok: false, reason: unpackDetail });
  }
  const reportLines: string[] = [`unpack ${unpackDetail}`];
  for (const result of results) {
    if (result.ok) reportLines.push(`ok ${result.ref}`);
    else reportLines.push(`ng ${result.ref} ${result.reason}`);
  }
  const parts: Buffer[] = [];
  for (const line of reportLines) {
    parts.push(pktLine(Buffer.concat([Buffer.from([1]), pktLine(`${line}\n`)])));
  }
  parts.push(PKT_FLUSH);
  sendBytes(res, 200, Buffer.concat(parts), 'application/x-git-receive-pack-result');
}

// ---------------------------------------------------------------------------
// REST v3: /api/v3
// ---------------------------------------------------------------------------

function lookupRepoOr404(
  res: ServerResponse,
  owner: string,
  name: string,
): Repo | null {
  const repo = findRepo(owner, name);
  if (repo === null) {
    errorJson(res, 404, 'repository not found');
    return null;
  }
  return repo;
}

function parseNumber(value: string | null, fallback: number): number {
  if (value === null) return fallback;
  const parsed = parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function pageLinkHeader(req: IncomingMessage, basePath: string, query: URLSearchParams, page: number, perPage: number, hasNext: boolean): string | null {
  if (!hasNext) return null;
  const host = req.headers.host ?? '127.0.0.1';
  const next = new URLSearchParams(query);
  next.set('page', String(page + 1));
  next.set('per_page', String(perPage));
  const url = `http://${host}${basePath}?${next.toString()}`;
  return `<${url}>; rel="next"`;
}

function paginate<T>(items: T[], page: number, perPage: number): { page: T[]; hasNext: boolean } {
  const start = (page - 1) * perPage;
  const slice = items.slice(start, start + perPage);
  return { page: slice, hasNext: start + perPage < items.length };
}

async function handleRest(req: IncomingMessage, res: ServerResponse, segments: string[], query: URLSearchParams): Promise<void> {
  const method = req.method ?? 'GET';
  const bodyText = method === 'GET' || method === 'DELETE' && segments.join('/').indexOf('contents') < 0 ? null : await readBody(req);
  void bodyText;
  const body = bodyText === null || bodyText.length === 0 ? null : parseJsonBody(bodyText);
  if (body === undefined) {
    errorJson(res, 400, 'malformed JSON body');
    return;
  }

  // GET /api/v3/ and /api/v3/meta and /api/v3/user
  if (segments.length === 0) {
    if (method === 'GET') {
      sendJson(res, 200, { current_user_url: '/api/v3/user', repository_url: '/api/v3/repos/{owner}/{repo}' }, { 'x-oauth-scopes': 'repo, read:org' });
    } else {
      errorJson(res, 404, 'unknown route');
    }
    return;
  }
  if (segments[0] === 'meta' && segments.length === 1) {
    if (method === 'GET') sendJson(res, 200, { installed_version: '1.0.0' });
    else errorJson(res, 404, 'unknown route');
    return;
  }
  if (segments[0] === 'user' && segments.length === 1) {
    if (method === 'GET') {
      sendJson(res, 200, { login: VIEWER_LOGIN, id: VIEWER_ID, name: VIEWER_NAME, email: VIEWER_EMAIL, type: 'User' });
    } else {
      errorJson(res, 404, 'unknown route');
    }
    return;
  }

  // /api/v3/user/repos
  if (segments[0] === 'user' && segments[1] === 'repos' && segments.length === 2) {
    if (method === 'GET') {
      const perPage = Math.min(100, Math.max(1, parseNumber(query.get('per_page'), 30)));
      const page = Math.max(1, parseNumber(query.get('page'), 1));
      const all = [...repos.values()].map(repoJson);
      const sliced = paginate(all, page, perPage);
      const link = pageLinkHeader(req, '/api/v3/user/repos', query, page, perPage, sliced.hasNext);
      sendJson(res, 200, sliced.page, link === null ? {} : { link });
      return;
    }
    if (method === 'POST') {
      if (!isRecord(body)) {
        errorJson(res, 422, 'repository name is required');
        return;
      }
      const name = body.name;
      if (typeof name !== 'string' || name === '' || /[/\s]/.test(name) || name.startsWith('.')) {
        errorJson(res, 422, 'invalid repository name');
        return;
      }
      if (repos.has(repoKey(VIEWER_LOGIN, name))) {
        errorJson(res, 422, `repository ${name} already exists`);
        return;
      }
      const description = typeof body.description === 'string' ? body.description : '';
      const isPrivate = body.private === true;
      const defaultBranch = typeof body.default_branch === 'string' ? body.default_branch : 'main';
      const repo = createRepoRecord(name, description, isPrivate, defaultBranch);
      repos.set(repoKey(VIEWER_LOGIN, name), repo);
      sendJson(res, 201, repoJson(repo));
      return;
    }
    errorJson(res, 404, 'unknown route');
    return;
  }

  // /api/v3/repos/{owner}/{repo}[...]
  if (segments[0] === 'repos' && segments.length >= 3) {
    const owner = segments[1];
    const name = segments[2];
    const rest = segments.slice(3);
    const repo = lookupRepoOr404(res, owner, name);
    if (repo === null) return;

    if (rest.length === 0) {
      if (method === 'GET') {
        sendJson(res, 200, repoJson(repo));
        return;
      }
      if (method === 'PATCH') {
        if (isRecord(body)) {
          if (typeof body.description === 'string') repo.description = body.description;
          if (typeof body.private === 'boolean') repo.isPrivate = body.private;
          if (typeof body.default_branch === 'string' && body.default_branch !== '') repo.defaultBranch = body.default_branch;
          repo.updatedAt = nextIso();
        }
        sendJson(res, 200, repoJson(repo));
        return;
      }
      if (method === 'DELETE') {
        repos.delete(repoKey(owner, name));
        res.writeHead(204, { 'x-github-request-id': nextRequestId() });
        res.end();
        return;
      }
      errorJson(res, 404, 'unknown route');
      return;
    }

    if (rest[0] === 'branches') {
      if (rest.length === 1 && method === 'GET') {
        const list = [...repo.refs.keys()]
          .filter((ref) => ref.startsWith('refs/heads/'))
          .map((ref) => ref.slice('refs/heads/'.length))
          .sort()
          .map((branch) => ({ name: branch, commit: { sha: repo.refs.get(`refs/heads/${branch}`) as string } }));
        sendJson(res, 200, list);
        return;
      }
      if (rest.length === 2 && method === 'GET') {
        const sha = repo.refs.get(`refs/heads/${rest[1]}`);
        if (sha === undefined) {
          errorJson(res, 404, 'branch not found');
          return;
        }
        sendJson(res, 200, { name: rest[1], commit: { sha } });
        return;
      }
      errorJson(res, 404, 'unknown route');
      return;
    }

    if (rest[0] === 'commits') {
      if (method === 'GET') {
        const ref = query.get('sha') ?? repo.defaultBranch;
        const tip = resolveCommitTip(repo.objects, repo.refs, ref);
        if (tip === null) {
          errorJson(res, 404, 'no commits');
          return;
        }
        const commits = listCommits(repo.objects, tip, 100).map((sha) => {
          const parts = parseCommit((repo.objects.get(sha) as GitObject).data);
          const message = parts.message.endsWith('\n') ? parts.message.slice(0, -1) : parts.message;
          const authorEpoch = parts.author.match(/(\d+) \+0000$/)?.[1];
          const date = authorEpoch === undefined ? repo.createdAt : new Date(Number(authorEpoch) * 1000).toISOString();
          return {
            sha,
            commit: {
              message,
              author: { name: VIEWER_NAME, email: VIEWER_EMAIL, date },
              committer: { name: VIEWER_NAME, email: VIEWER_EMAIL, date },
            },
          };
        });
        sendJson(res, 200, commits);
        return;
      }
      errorJson(res, 404, 'unknown route');
      return;
    }

    if (rest[0] === 'git' && rest[1] === 'refs') {
      if (rest.length === 2 && method === 'GET') {
        const list = [...repo.refs.entries()].sort().map(([ref, sha]) => {
          const object = repo.objects.get(sha);
          return { ref, object: { sha, type: object === undefined ? 'commit' : object.type } };
        });
        sendJson(res, 200, list);
        return;
      }
      if (rest.length === 2 && method === 'POST') {
        if (!isRecord(body) || typeof body.ref !== 'string' || typeof body.sha !== 'string') {
          errorJson(res, 422, 'ref and sha are required');
          return;
        }
        if (!body.ref.startsWith('refs/')) {
          errorJson(res, 422, 'ref must start with refs/');
          return;
        }
        if (repo.refs.has(body.ref)) {
          errorJson(res, 422, 'ref already exists');
          return;
        }
        const object = repo.objects.get(body.sha);
        if (object === undefined) {
          errorJson(res, 422, 'object does not exist');
          return;
        }
        repo.refs.set(body.ref, body.sha);
        sendJson(res, 201, { ref: body.ref, object: { sha: body.sha, type: object.type } });
        return;
      }
      if (rest.length === 4 && rest[2] === 'heads' && method === 'GET') {
        const sha = repo.refs.get(`refs/heads/${rest[3]}`);
        if (sha === undefined) {
          errorJson(res, 404, 'ref not found');
          return;
        }
        const object = repo.objects.get(sha);
        sendJson(res, 200, { ref: `refs/heads/${rest[3]}`, object: { sha, type: object === undefined ? 'commit' : object.type } });
        return;
      }
      errorJson(res, 404, 'unknown route');
      return;
    }

    if (rest[0] === 'contents') {
      const path = rest.slice(1).join('/');
      if (method === 'GET') {
        const ref = query.get('ref') ?? repo.defaultBranch;
        const tip = resolveCommitTip(repo.objects, repo.refs, ref);
        if (tip === null) {
          errorJson(res, 404, 'repository is empty');
          return;
        }
        if (path === '') {
          const found = lookupPath(repo.objects, tip, '');
          if (found === null || found.kind !== 'dir') {
            errorJson(res, 404, 'path not found');
            return;
          }
          const rootTree = parseCommit((repo.objects.get(tip) as GitObject).data).tree;
          const entries = parseTree((repo.objects.get(rootTree) as GitObject).data).map((entry) => ({
            type: entry.mode === '40000' ? 'dir' : 'file',
            name: entry.name,
            path: entry.name,
            sha: entry.oid,
          }));
          sendJson(res, 200, entries);
          return;
        }
        const found = lookupPath(repo.objects, tip, path);
        if (found === null) {
          errorJson(res, 404, 'path not found');
          return;
        }
        if (found.kind === 'file') {
          const object = repo.objects.get(found.oid) as GitObject;
          sendJson(res, 200, {
            type: 'file',
            encoding: 'base64',
            content: object.data.toString('base64'),
            sha: found.oid,
            size: object.data.length,
            name: path.split('/').pop(),
            path,
          });
          return;
        }
        const entries: Array<Record<string, unknown>> = [];
        const treeObject = repo.objects.get(found.treeOid);
        if (treeObject !== undefined) {
          for (const entry of parseTree(treeObject.data)) {
            entries.push({
              type: entry.mode === '40000' ? 'dir' : 'file',
              name: entry.name,
              path: `${path}/${entry.name}`,
              sha: entry.oid,
            });
          }
        }
        sendJson(res, 200, entries);
        return;
      }
      if (method === 'PUT') {
        if (!isRecord(body) || typeof body.content !== 'string' || typeof body.message !== 'string') {
          errorJson(res, 422, 'content and message are required');
          return;
        }
        const branch = typeof body.branch === 'string' && body.branch !== '' ? body.branch : repo.defaultBranch;
        const existingTip = resolveCommitTip(repo.objects, repo.refs, branch);
        let existingBlob: string | null = null;
        if (existingTip !== null) {
          const found = lookupPath(repo.objects, existingTip, path);
          if (found !== null && found.kind === 'file') existingBlob = found.oid;
        }
        if (typeof body.sha === 'string' && existingBlob !== null && body.sha !== existingBlob) {
          errorJson(res, 409, 'sha does not match the current file');
          return;
        }
        const isNew = existingBlob === null;
        const content = Buffer.from(body.content, 'base64');
        const result = commitFileChange(repo, branch, path, content, body.message);
        const status = isNew ? 201 : 200;
        sendJson(res, status, {
          content: { name: path.split('/').pop(), path, sha: result.blobSha, size: content.length, encoding: 'base64' },
          commit: { sha: result.commitSha, message: body.message },
        });
        return;
      }
      if (method === 'DELETE') {
        if (!isRecord(body) || typeof body.message !== 'string') {
          errorJson(res, 422, 'message is required');
          return;
        }
        const branch = typeof body.branch === 'string' && body.branch !== '' ? body.branch : repo.defaultBranch;
        const tip = resolveCommitTip(repo.objects, repo.refs, branch);
        if (tip === null) {
          errorJson(res, 404, 'repository is empty');
          return;
        }
        const found = lookupPath(repo.objects, tip, path);
        if (found === null || found.kind !== 'file') {
          errorJson(res, 404, 'path not found');
          return;
        }
        const result = commitFileChange(repo, branch, path, null, body.message);
        sendJson(res, 200, { commit: { sha: result.commitSha, message: body.message } });
        return;
      }
      errorJson(res, 404, 'unknown route');
      return;
    }

    if (rest[0] === 'labels') {
      if (rest.length === 1 && method === 'GET') {
        sendJson(res, 200, [...repo.labels.values()]);
        return;
      }
      if (rest.length === 1 && method === 'POST') {
        if (!isRecord(body) || typeof body.name !== 'string' || body.name === '') {
          errorJson(res, 422, 'label name is required');
          return;
        }
        const existing = repo.labels.get(body.name);
        if (existing !== undefined) {
          sendJson(res, 200, existing);
          return;
        }
        const label = { name: body.name, color: typeof body.color === 'string' ? body.color : 'ededed' };
        repo.labels.set(label.name, label);
        sendJson(res, 201, label);
        return;
      }
      errorJson(res, 404, 'unknown route');
      return;
    }

    if (rest[0] === 'issues') {
      if (rest.length === 1) {
        if (method === 'GET') {
          const state = query.get('state') ?? 'open';
          const sort = query.get('sort') ?? 'created';
          const direction = query.get('direction') ?? 'desc';
          let list = [...repo.issues.values()];
          if (state !== 'all') list = list.filter((issue) => issue.state === state);
          if (sort === 'comments') {
            list.sort((a, b) => (direction === 'asc' ? a.comments.length - b.comments.length : b.comments.length - a.comments.length));
          } else {
            list.sort((a, b) => (direction === 'asc' ? a.number - b.number : b.number - a.number));
          }
          const perPage = Math.min(100, Math.max(1, parseNumber(query.get('per_page'), 30)));
          const page = Math.max(1, parseNumber(query.get('page'), 1));
          const sliced = paginate(list, page, perPage);
          const link = pageLinkHeader(req, `/api/v3/repos/${owner}/${name}/issues`, query, page, perPage, sliced.hasNext);
          sendJson(res, 200, sliced.page.map((issue) => issueJson(repo, issue)), link === null ? {} : { link });
          return;
        }
        if (method === 'POST') {
          if (!isRecord(body) || typeof body.title !== 'string' || body.title === '') {
            errorJson(res, 422, 'title is required');
            return;
          }
          const labels: string[] = Array.isArray(body.labels) ? body.labels.filter((entry): entry is string => typeof entry === 'string') : [];
          for (const label of labels) {
            if (!repo.labels.has(label)) {
              errorJson(res, 422, `label "${label}" does not exist`);
              return;
            }
          }
          const number = repo.nextNumber++;
          const now = nextIso();
          const issue: Issue = {
            number,
            title: body.title,
            body: typeof body.body === 'string' ? body.body : '',
            state: 'open',
            labels,
            createdAt: now,
            updatedAt: now,
            closedAt: null,
            comments: [],
          };
          repo.issues.set(number, issue);
          sendJson(res, 201, issueJson(repo, issue));
          return;
        }
        errorJson(res, 404, 'unknown route');
        return;
      }
      const issueNumber = Number(rest[1]);
      if (!Number.isInteger(issueNumber)) {
        errorJson(res, 404, 'unknown route');
        return;
      }
      const issue = repo.issues.get(issueNumber);
      if (rest.length === 2) {
        if (issue === undefined) {
          errorJson(res, 404, 'issue not found');
          return;
        }
        if (method === 'GET') {
          sendJson(res, 200, issueJson(repo, issue));
          return;
        }
        if (method === 'PATCH') {
          if (isRecord(body)) {
            if (typeof body.title === 'string') issue.title = body.title;
            if (typeof body.body === 'string') issue.body = body.body;
            if (body.state === 'closed' && issue.state !== 'closed') {
              issue.state = 'closed';
              issue.closedAt = nextIso();
            } else if (body.state === 'open' && issue.state !== 'open') {
              issue.state = 'open';
              issue.closedAt = null;
            }
            if (Array.isArray(body.labels)) {
              const labels = body.labels.filter((entry): entry is string => typeof entry === 'string');
              for (const label of labels) {
                if (!repo.labels.has(label)) {
                  errorJson(res, 422, `label "${label}" does not exist`);
                  return;
                }
              }
              issue.labels = labels;
            }
            issue.updatedAt = nextIso();
          }
          sendJson(res, 200, issueJson(repo, issue));
          return;
        }
        errorJson(res, 404, 'unknown route');
        return;
      }
      if (rest.length === 3 && rest[2] === 'comments') {
        if (issue === undefined) {
          errorJson(res, 404, 'issue not found');
          return;
        }
        if (method === 'GET') {
          sendJson(res, 200, issue.comments.map((comment) => ({ id: comment.id, body: comment.body, created_at: comment.createdAt, user: { login: VIEWER_LOGIN, id: VIEWER_ID } })));
          return;
        }
        if (method === 'POST') {
          if (!isRecord(body) || typeof body.body !== 'string') {
            errorJson(res, 422, 'body is required');
            return;
          }
          const comment = { id: repo.nextCommentId++, body: body.body, createdAt: nextIso() };
          issue.comments.push(comment);
          issue.updatedAt = nextIso();
          sendJson(res, 201, { id: comment.id, body: comment.body, created_at: comment.createdAt, user: { login: VIEWER_LOGIN, id: VIEWER_ID } });
          return;
        }
        errorJson(res, 404, 'unknown route');
        return;
      }
      errorJson(res, 404, 'unknown route');
      return;
    }

    if (rest[0] === 'pulls') {
      if (rest.length === 1) {
        if (method === 'GET') {
          const state = query.get('state') ?? 'open';
          let list = [...repo.pulls.values()];
          if (state !== 'all') list = list.filter((pull) => pull.state === state);
          list.sort((a, b) => b.number - a.number);
          const perPage = Math.min(100, Math.max(1, parseNumber(query.get('per_page'), 30)));
          const page = Math.max(1, parseNumber(query.get('page'), 1));
          const sliced = paginate(list, page, perPage);
          const link = pageLinkHeader(req, `/api/v3/repos/${owner}/${name}/pulls`, query, page, perPage, sliced.hasNext);
          sendJson(res, 200, sliced.page.map((pull) => pullJson(repo, pull)), link === null ? {} : { link });
          return;
        }
        if (method === 'POST') {
          if (!isRecord(body) || typeof body.title !== 'string' || body.title === '' || typeof body.head !== 'string' || typeof body.base !== 'string') {
            errorJson(res, 422, 'title, head and base are required');
            return;
          }
          const head = body.head.includes(':') ? body.head.split(':').pop() as string : body.head;
          const base = body.base.includes(':') ? body.base.split(':').pop() as string : body.base;
          const headSha = resolveCommitTip(repo.objects, repo.refs, head);
          const baseSha = resolveCommitTip(repo.objects, repo.refs, base);
          if (headSha === null) {
            errorJson(res, 422, `head branch ${head} does not exist`);
            return;
          }
          if (baseSha === null) {
            errorJson(res, 422, `base branch ${base} does not exist`);
            return;
          }
          const number = repo.nextNumber++;
          const now = nextIso();
          const pull: PullRequest = {
            number,
            title: body.title,
            body: typeof body.body === 'string' ? body.body : '',
            state: 'open',
            merged: false,
            mergedAt: null,
            mergeCommitSha: null,
            head,
            base,
            headSha,
            baseSha,
            createdAt: now,
            updatedAt: now,
          };
          repo.pulls.set(number, pull);
          sendJson(res, 201, pullJson(repo, pull));
          return;
        }
        errorJson(res, 404, 'unknown route');
        return;
      }
      const pullNumber = Number(rest[1]);
      if (!Number.isInteger(pullNumber)) {
        errorJson(res, 404, 'unknown route');
        return;
      }
      const pull = repo.pulls.get(pullNumber);
      if (rest.length === 2) {
        if (pull === undefined) {
          errorJson(res, 404, 'pull request not found');
          return;
        }
        if (method === 'GET') {
          sendJson(res, 200, pullJson(repo, pull));
          return;
        }
        errorJson(res, 404, 'unknown route');
        return;
      }
      if (rest.length === 3 && rest[2] === 'files' && method === 'GET') {
        if (pull === undefined) {
          errorJson(res, 404, 'pull request not found');
          return;
        }
        const files = prFiles(repo, pull).map((line) => ({
          filename: line.path,
          status: line.status === 'deleted' ? 'changed' : line.status,
          additions: line.additions,
          deletions: line.deletions,
          changes: line.changes,
        }));
        sendJson(res, 200, files);
        return;
      }
      if (rest.length === 3 && rest[2] === 'merge' && method === 'PUT') {
        if (pull === undefined) {
          errorJson(res, 404, 'pull request not found');
          return;
        }
        if (pull.merged) {
          errorJson(res, 405, 'pull request is already merged');
          return;
        }
        if (prConflicts(repo, pull)) {
          errorJson(res, 405, 'merge conflict');
          return;
        }
        const sha = squashMerge(repo, pull);
        sendJson(res, 200, { sha, merged: true, message: `Merge pull request #${pull.number} from ${repo.owner}/${pull.head}` });
        return;
      }
      errorJson(res, 404, 'unknown route');
      return;
    }

    errorJson(res, 404, 'unknown route');
    return;
  }

  errorJson(res, 404, 'unknown route');
}

// ---------------------------------------------------------------------------
// Git smart HTTP: /{owner}/{repo}.git/*
// ---------------------------------------------------------------------------

async function handleGit(req: IncomingMessage, res: ServerResponse, owner: string, name: string, rest: string[], query: URLSearchParams): Promise<void> {
  const method = req.method ?? 'GET';
  const repo = findRepo(owner, name);
  if (rest[0] === 'info' && rest[1] === 'refs') {
    const service = query.get('service');
    if (service === 'git-upload-pack') {
      handleInfoRefs(req, res, owner, name, 'git-upload-pack');
      return;
    }
    if (service === 'git-receive-pack') {
      handleInfoRefs(req, res, owner, name, 'git-receive-pack');
      return;
    }
    errorJson(res, 400, 'unknown service');
    return;
  }
  if (rest[0] === 'git-upload-pack' && method === 'POST') {
    await handleUploadPack(req, res, repo);
    return;
  }
  if (rest[0] === 'git-receive-pack' && method === 'POST') {
    await handleReceivePack(req, res, repo);
    return;
  }
  errorJson(res, 404, 'unknown route');
}

// ---------------------------------------------------------------------------
// GraphQL: /api/graphql
// ---------------------------------------------------------------------------

const EXT_LANGUAGE: Record<string, { name: string; color: string }> = {
  '.py': { name: 'Python', color: '3572A5' },
  '.ts': { name: 'TypeScript', color: '3178c6' },
  '.tsx': { name: 'TypeScript', color: '3178c6' },
  '.js': { name: 'JavaScript', color: 'f1e05a' },
  '.jsx': { name: 'JavaScript', color: 'f1e05a' },
  '.go': { name: 'Go', color: '00ADD8' },
  '.rs': { name: 'Rust', color: 'dea584' },
  '.rb': { name: 'Ruby', color: '701516' },
  '.java': { name: 'Java', color: 'b07219' },
  '.c': { name: 'C', color: '555555' },
  '.cpp': { name: 'C++', color: 'f34b7d' },
  '.cs': { name: 'C#', color: '178600' },
  '.sh': { name: 'Shell', color: '89e051' },
  '.md': { name: 'Markdown', color: '083fa1' },
  '.json': { name: 'JSON', color: '292929' },
  '.html': { name: 'HTML', color: 'e34c26' },
  '.css': { name: 'CSS', color: '663399' },
};

function repoLanguages(repo: Repo): Array<{ name: string; color: string }> {
  const tip = resolveCommitTip(repo.objects, repo.refs, repo.defaultBranch);
  if (tip === null) return [];
  const counts = new Map<string, number>();
  for (const file of flattenTree(repo.objects, tip)) {
    const dot = file.path.lastIndexOf('.');
    if (dot < 0) continue;
    const lang = EXT_LANGUAGE[file.path.slice(dot)];
    if (lang === undefined) continue;
    counts.set(lang.name, (counts.get(lang.name) ?? 0) + 1);
  }
  const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1));
  const byName = new Map<string, { name: string; color: string }>();
  for (const value of Object.values(EXT_LANGUAGE)) byName.set(value.name, value);
  return sorted.map(([name]) => byName.get(name) as { name: string; color: string });
}

function issueByGlobalId(id: string): { repo: Repo; issue: Issue } | null {
  const parsed = parseGlobalId(id);
  if (parsed === null || parsed.kind !== 'Issue' || parsed.num === undefined) return null;
  for (const repo of repos.values()) {
    if (repo.databaseId !== parsed.dbid) continue;
    const issue = repo.issues.get(parsed.num);
    if (issue !== undefined) return { repo, issue };
  }
  return null;
}

function pullByGlobalId(id: string): { repo: Repo; pull: PullRequest } | null {
  const parsed = parseGlobalId(id);
  if (parsed === null || parsed.kind !== 'PullRequest' || parsed.num === undefined) return null;
  for (const repo of repos.values()) {
    if (repo.databaseId !== parsed.dbid) continue;
    const pull = repo.pulls.get(parsed.num);
    if (pull !== undefined) return { repo, pull };
  }
  return null;
}

function graphqlRepoShape(repo: Repo): Record<string, unknown> {
  return {
    id: globalId('Repository', repo.databaseId),
    databaseId: repo.databaseId,
    nameWithOwner: `${repo.owner}/${repo.name}`,
    name: repo.name,
    description: repo.description,
    owner: { login: repo.owner },
    defaultBranchRef: { name: repo.defaultBranch },
    viewerPermission: 'ADMIN',
    hasIssuesEnabled: true,
    issues: { totalCount: repo.issues.size },
    languages: { edges: repoLanguages(repo).slice(0, 1).map((lang) => ({ node: { name: lang.name, color: lang.color } })) },
  };
}

function toGraphqlState(state: string): string {
  return state === 'closed' ? 'CLOSED' : 'OPEN';
}

const GRAPHQL_TYPE_FIELDS: Record<string, string[]> = {
  Issue: ['id', 'number', 'title', 'state', 'body', 'labels', 'author', 'comments', 'createdAt', 'updatedAt', 'closedAt', 'url'],
  PullRequest: ['id', 'number', 'title', 'state', 'merged', 'headRefName', 'baseRefName', 'mergeable', 'files', 'body', 'createdAt', 'updatedAt', 'url'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'description', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequest', 'pullRequests', 'ref', 'refs', 'labels', 'languages', 'createdAt', 'updatedAt'],
  User: ['login', 'id', 'name', 'email'],
};

const GRAPHQL_TYPE_ENUMS: Record<string, string[]> = {
  SearchType: ['ISSUE', 'PULL_REQUEST', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT', 'MARKETPLACE_LISTING'],
};

function topLevelFields(queryText: string, starter: RegExp): string[] | null {
  const found = starter.exec(queryText);
  if (found === null || found.index === undefined) return null;
  let at = found.index + found[0].length;
  while (at < queryText.length && queryText[at] !== '{') at++;
  if (at >= queryText.length) return null;
  let braceDepth = 0;
  let parenDepth = 0;
  const fields: string[] = [];
  while (at < queryText.length) {
    const ch = queryText[at];
    if (ch === '{') {
      braceDepth++;
      at++;
      continue;
    }
    if (ch === '}') {
      braceDepth--;
      if (braceDepth === 0) break;
      at++;
      continue;
    }
    if (ch === '(') {
      parenDepth++;
      at++;
      continue;
    }
    if (ch === ')') {
      parenDepth--;
      at++;
      continue;
    }
    if (braceDepth === 1 && parenDepth === 0) {
      const word = /^[A-Za-z_][A-Za-z0-9_]*/.exec(queryText.slice(at));
      if (word !== null) {
        if (word[0] !== 'on' && !word[0].startsWith('__')) fields.push(word[0]);
        at += word[0].length;
        continue;
      }
    }
    at++;
  }
  return fields;
}

function graphqlError(message: string, data?: Record<string, unknown>): Record<string, unknown> {
  return { data: data ?? {}, errors: [{ message }] };
}

function runGraphqlOperation(payload: Record<string, unknown>): Record<string, unknown> {
  if (typeof payload.query !== 'string') return graphqlError('query is required');
  const queryText: string = payload.query;
  const variables: Record<string, unknown> = isRecord(payload.variables) ? payload.variables : {};
  const input: Record<string, unknown> = isRecord(variables.input) ? variables.input : variables;
  const owner = typeof variables.owner === 'string' ? variables.owner : '';
  const name = typeof variables.name === 'string' ? variables.name : '';
  const number = typeof variables.number === 'number' ? variables.number : -1;

  // __type introspection (gh's feature-detection probes use aliases).
  if (queryText.includes('__type(')) {
    const data: Record<string, unknown> = {};
    const pattern = /([A-Za-z_][A-Za-z0-9_]*)\s*:\s*__type\(\s*name\s*:\s*"([^"]+)"\s*\)\s*\{\s*(fields|enumValues)\s*\(/g;
    let match: RegExpExecArray | null;
    let foundAny = false;
    while ((match = pattern.exec(queryText)) !== null) {
      foundAny = true;
      if (match[3] === 'fields') {
        data[match[1]] = { fields: (GRAPHQL_TYPE_FIELDS[match[2]] ?? []).map((field) => ({ name: field })) };
      } else {
        data[match[1]] = { enumValues: (GRAPHQL_TYPE_ENUMS[match[2]] ?? []).map((value) => ({ name: value })) };
      }
    }
    if (foundAny) return { data };
    const plain = queryText.match(/__type\(\s*name\s*:\s*"([^"]+)"\s*\)\s*\{\s*(fields|enumValues)\s*\(/);
    if (plain !== null) {
      if (plain[2] === 'fields') {
        return { data: { __type: { fields: (GRAPHQL_TYPE_FIELDS[plain[1]] ?? []).map((field) => ({ name: field })) } } };
      }
      return { data: { __type: { enumValues: (GRAPHQL_TYPE_ENUMS[plain[1]] ?? []).map((value) => ({ name: value })) } } };
    }
  }

  // Relay node(id:) round-trip.
  if (/node\s*\(\s*id\s*:/.test(queryText)) {
    const id = typeof variables.id === 'string' ? variables.id : '';
    const parsed = parseGlobalId(id);
    if (parsed === null) return { data: { node: null } };
    if (parsed.kind === 'Repository') {
      for (const repo of repos.values()) {
        if (repo.databaseId === parsed.dbid) {
          return { data: { node: { id, name: repo.name, nameWithOwner: `${repo.owner}/${repo.name}` } } };
        }
      }
      return { data: { node: null } };
    }
    if ((parsed.kind === 'Issue' || parsed.kind === 'PullRequest') && parsed.num !== undefined) {
      for (const repo of repos.values()) {
        if (repo.databaseId !== parsed.dbid) continue;
        if (parsed.kind === 'Issue') {
          const issue = repo.issues.get(parsed.num);
          if (issue !== undefined) return { data: { node: { id, number: issue.number, title: issue.title } } };
        } else {
          const pull = repo.pulls.get(parsed.num);
          if (pull !== undefined) return { data: { node: { id, number: pull.number, title: pull.title } } };
        }
      }
      return { data: { node: null } };
    }
    return { data: { node: null } };
  }

  // Mutations (matched on the mutation field name; variables arrive as $input or flat).
  if (queryText.includes('updateIssue(')) {
    const found = typeof input.id === 'string' ? issueByGlobalId(input.id) : null;
    if (found === null) return graphqlError('issue not found');
    if (typeof input.title === 'string') found.issue.title = input.title;
    if (input.state === 'closed' && found.issue.state !== 'closed') {
      found.issue.state = 'closed';
      found.issue.closedAt = nextIso();
    } else if (input.state === 'open' && found.issue.state !== 'open') {
      found.issue.state = 'open';
      found.issue.closedAt = null;
    }
    found.issue.updatedAt = nextIso();
    return { data: { updateIssue: { issue: { id: input.id, title: found.issue.title, state: toGraphqlState(found.issue.state) } } } };
  }
  if (queryText.includes('updateRepository(')) {
    const repo = typeof input.repositoryId === 'string' ? repoByGlobalId(input.repositoryId) : null;
    if (repo === null) return graphqlError('repository not found');
    if (typeof input.description === 'string') repo.description = input.description;
    repo.updatedAt = nextIso();
    return { data: { updateRepository: { repository: { description: repo.description } } } };
  }
  if (queryText.includes('closeIssue(')) {
    const found = typeof input.issueId === 'string' ? issueByGlobalId(input.issueId) : null;
    if (found === null) return graphqlError('issue not found');
    if (found.issue.state !== 'closed') {
      found.issue.state = 'closed';
      found.issue.closedAt = nextIso();
    }
    found.issue.updatedAt = nextIso();
    return { data: { closeIssue: { issue: { number: found.issue.number, id: input.issueId, state: 'CLOSED' } } } };
  }
  if (queryText.includes('createIssue(')) {
    const repo = typeof input.repositoryId === 'string' ? repoByGlobalId(input.repositoryId) : null;
    if (repo === null) return graphqlError('repository not found');
    if (typeof input.title !== 'string' || input.title === '') return graphqlError('title is required');
    const num = repo.nextNumber++;
    const now = nextIso();
    const issue: Issue = {
      number: num,
      title: input.title,
      body: typeof input.body === 'string' ? input.body : '',
      state: 'open',
      labels: [],
      createdAt: now,
      updatedAt: now,
      closedAt: null,
      comments: [],
    };
    repo.issues.set(num, issue);
    return { data: { createIssue: { issue: { id: globalId('Issue', repo.databaseId, num), number: num, title: issue.title } } } };
  }
  if (queryText.includes('createPullRequest(')) {
    const repo = typeof input.repositoryId === 'string' ? repoByGlobalId(input.repositoryId) : null;
    if (repo === null) return graphqlError('repository not found');
    if (typeof input.title !== 'string' || typeof input.headRefName !== 'string' || typeof input.baseRefName !== 'string') {
      return graphqlError('title, headRefName and baseRefName are required');
    }
    const headSha = resolveCommitTip(repo.objects, repo.refs, input.headRefName);
    const baseSha = resolveCommitTip(repo.objects, repo.refs, input.baseRefName);
    if (headSha === null) return graphqlError(`head branch ${input.headRefName} does not exist`);
    if (baseSha === null) return graphqlError(`base branch ${input.baseRefName} does not exist`);
    const num = repo.nextNumber++;
    const now = nextIso();
    const pull: PullRequest = {
      number: num,
      title: input.title,
      body: typeof input.body === 'string' ? input.body : '',
      state: 'open',
      merged: false,
      mergedAt: null,
      mergeCommitSha: null,
      head: input.headRefName,
      base: input.baseRefName,
      headSha,
      baseSha,
      createdAt: now,
      updatedAt: now,
    };
    repo.pulls.set(num, pull);
    return { data: { createPullRequest: { pullRequest: { number: num, id: globalId('PullRequest', repo.databaseId, num), state: 'OPEN', headRefName: pull.head, baseRefName: pull.base } } } };
  }
  if (queryText.includes('mergePullRequest(')) {
    const found = typeof input.pullRequestId === 'string' ? pullByGlobalId(input.pullRequestId) : null;
    if (found === null) return graphqlError('pull request not found');
    if (found.pull.merged) {
      return { data: { mergePullRequest: { pullRequest: { number: found.pull.number, merged: true, state: 'MERGED' } } } };
    }
    if (prConflicts(found.repo, found.pull)) return graphqlError('merge conflict');
    squashMerge(found.repo, found.pull);
    return { data: { mergePullRequest: { pullRequest: { number: found.pull.number, merged: true, state: 'MERGED' } } } };
  }
  if (queryText.includes('addComment(')) {
    const found = typeof input.subjectId === 'string' ? issueByGlobalId(input.subjectId) : null;
    if (found === null) return graphqlError('issue not found');
    if (typeof input.body !== 'string') return graphqlError('body is required');
    const comment = { id: found.repo.nextCommentId++, body: input.body, createdAt: nextIso() };
    found.issue.comments.push(comment);
    found.issue.updatedAt = nextIso();
    return { data: { addComment: { commentEdge: { node: { id: globalId('IssueComment', found.repo.databaseId, comment.id), body: comment.body } } } } };
  }

  // Search (viewer issues by repo + keyword).
  if (queryText.includes('search(')) {
    const searchQuery = typeof variables.query === 'string' ? variables.query : '';
    const repoToken = searchQuery.match(/repo:([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.\-]+)/);
    const keywords = searchQuery.replace(/repo:[^\s]+/g, '').split(/\s+/).filter((word) => word !== '');
    const nodes: Array<Record<string, unknown>> = [];
    if (repoToken !== null) {
      const repo = findRepo(repoToken[1], repoToken[2]);
      if (repo !== null) {
        for (const issue of repo.issues.values()) {
          const haystack = `${issue.title} ${issue.body}`.toLowerCase();
          if (keywords.length === 0 || keywords.some((word) => haystack.includes(word.toLowerCase()))) {
            nodes.push({ title: issue.title });
          }
        }
      }
    }
    return { data: { search: { nodes } } };
  }

  // Viewer (matched as a field, never as a substring of viewerPermission).
  if (/\bviewer\b/.test(queryText)) {
    const fields = topLevelFields(queryText, /\bviewer\b/);
    if (fields !== null) {
      for (const field of fields) {
        if (!['login', 'id', 'name', 'email'].includes(field)) {
          return graphqlError(`Cannot query field "${field}" on type "User".`, { viewer: { login: VIEWER_LOGIN } });
        }
      }
    }
    return { data: { viewer: { login: VIEWER_LOGIN, id: VIEWER_ID, name: VIEWER_NAME, email: VIEWER_EMAIL } } };
  }

  // Repository queries.
  if (/repository\s*\(/.test(queryText)) {
    const repo = findRepo(owner, name);
    if (repo === null) {
      return { data: { repository: null } };
    }
    if (queryText.includes('comments(first')) {
      const issue = repo.issues.get(number);
      if (issue === undefined) return { data: { repository: { issue: null } } };
      return { data: { repository: { issue: { comments: { nodes: issue.comments.map((comment) => ({ body: comment.body })) } } } } };
    }
    if (queryText.includes('issue(number:')) {
      const issue = repo.issues.get(number);
      if (issue === undefined) return { data: { repository: { issue: null } } };
      return {
        data: {
          repository: {
            issue: {
              id: globalId('Issue', repo.databaseId, issue.number),
              number: issue.number,
              title: issue.title,
              state: toGraphqlState(issue.state),
              body: issue.body,
              labels: { nodes: issue.labels.map((label) => ({ name: label })) },
              author: { login: VIEWER_LOGIN },
            },
          },
        },
      };
    }
    if (queryText.includes('pullRequest(number:')) {
      const pull = repo.pulls.get(number);
      if (pull === undefined) return { data: { repository: { pullRequest: null } } };
      const files = prFiles(repo, pull).map((line) => ({ path: line.path, additions: line.additions, deletions: line.deletions }));
      return {
        data: {
          repository: {
            pullRequest: {
              id: globalId('PullRequest', repo.databaseId, pull.number),
              number: pull.number,
              title: pull.title,
              state: pull.merged ? 'MERGED' : toGraphqlState(pull.state),
              merged: pull.merged,
              headRefName: pull.head,
              baseRefName: pull.base,
              mergeable: prConflicts(repo, pull) ? 'CONFLICTING' : 'MERGEABLE',
              files: { nodes: files },
            },
          },
        },
      };
    }
    if (queryText.includes('issues(first')) {
      const literal = queryText.match(/issues\(first:\s*(\d+)/);
      const pageSize = typeof variables.first === 'number' ? variables.first : (literal !== null ? parseInt(literal[1], 10) : 2);
      const afterSeq = typeof variables.after === 'string' ? decodeCursor(variables.after) : 0;
      let sorted = [...repo.issues.values()];
      if (queryText.includes('states: [OPEN]')) sorted = sorted.filter((issue) => issue.state === 'open');
      if (queryText.includes('states: [CLOSED]')) sorted = sorted.filter((issue) => issue.state === 'closed');
      if (queryText.includes('direction: DESC')) sorted.sort((a, b) => b.number - a.number);
      else sorted.sort((a, b) => a.number - b.number);
      const slice = sorted.slice(afterSeq, afterSeq + pageSize);
      const lastSeq = afterSeq + slice.length;
      const endCursor = slice.length === 0 ? null : encodeCursor(lastSeq);
      const nodes = slice.map((issue) => ({ id: globalId('Issue', repo.databaseId, issue.number), number: issue.number, title: issue.title, state: toGraphqlState(issue.state) }));
      return { data: { repository: { issues: { nodes, pageInfo: { hasNextPage: lastSeq < sorted.length, endCursor } } } } };
    }
    if (queryText.includes('pullRequests(first')) {
      const literal = queryText.match(/pullRequests\(first:\s*(\d+)/);
      const pageSize = typeof variables.first === 'number' ? variables.first : (literal !== null ? parseInt(literal[1], 10) : 2);
      const afterSeq = typeof variables.after === 'string' ? decodeCursor(variables.after) : 0;
      const sorted = [...repo.pulls.values()].sort((a, b) => a.number - b.number);
      const slice = sorted.slice(afterSeq, afterSeq + pageSize);
      const lastSeq = afterSeq + slice.length;
      const endCursor = slice.length === 0 ? null : encodeCursor(lastSeq);
      const nodes = slice.map((pull) => ({
        id: globalId('PullRequest', repo.databaseId, pull.number),
        number: pull.number,
        title: pull.title,
        state: pull.merged ? 'MERGED' : toGraphqlState(pull.state),
        headRefName: pull.head,
        baseRefName: pull.base,
        mergeable: prConflicts(repo, pull) ? 'CONFLICTING' : 'MERGEABLE',
      }));
      return { data: { repository: { pullRequests: { nodes, pageInfo: { hasNextPage: lastSeq < sorted.length, endCursor } } } } };
    }
    if (queryText.includes('ref(qualifiedName:')) {
      const refName = typeof variables.ref === 'string' ? variables.ref : repo.defaultBranch;
      const tip = resolveCommitTip(repo.objects, repo.refs, refName);
      if (tip === null) return { data: { repository: { ref: null } } };
      const nodes = listCommits(repo.objects, tip, 5).map((sha) => {
        const parts = parseCommit((repo.objects.get(sha) as GitObject).data);
        const message = parts.message.endsWith('\n') ? parts.message.slice(0, -1) : parts.message;
        return { oid: sha, message };
      });
      return { data: { repository: { ref: { target: { history: { nodes } } } } } };
    }
    if (queryText.includes('refs(first')) {
      const nodes = [...repo.refs.keys()]
        .filter((ref) => ref.startsWith('refs/heads/'))
        .map((ref) => ref.slice('refs/heads/'.length))
        .sort()
        .map((branch) => ({ name: branch }));
      return { data: { repository: { refs: { nodes } } } };
    }
    if (queryText.includes('labels(first')) {
      const nodes = [...repo.labels.values()].map((label) => ({ name: label.name, color: label.color }));
      return { data: { repository: { labels: { nodes } } } };
    }
    // Anything else in the repository block: a full repository read, unless it
    // asks for a field the schema does not hold.
    const fields = topLevelFields(queryText, /repository\s*\(/);
    if (fields !== null) {
      const known = ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'description', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequest', 'pullRequests', 'ref', 'refs', 'labels', 'languages', 'createdAt', 'updatedAt'];
      for (const field of fields) {
        if (!known.includes(field)) {
          return graphqlError(`Cannot query field "${field}" on type "Repository".`);
        }
      }
    }
    return { data: { repository: graphqlRepoShape(repo) } };
  }

  // Unknown top-level field.
  const topMatch = queryText.match(/\{\s*([A-Za-z_][A-Za-z0-9_]*)/);
  const topField = topMatch !== null ? topMatch[1] : 'field';
  return graphqlError(`Cannot query field "${topField}" on type "Query".`);
}

async function handleGraphql(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const text = await readBody(req);
  let payload: unknown;
  try {
    payload = JSON.parse(text);
  } catch {
    sendJson(res, 400, { errors: [{ message: 'parse error' }] });
    return;
  }
  if (Array.isArray(payload)) {
    const results = payload.map((entry) => (isRecord(entry) ? runGraphqlOperation(entry) : graphqlError('query is required')));
    sendJson(res, 200, results);
    return;
  }
  if (!isRecord(payload)) {
    sendJson(res, 400, { errors: [{ message: 'query is required' }] });
    return;
  }
  sendJson(res, 200, runGraphqlOperation(payload));
}

function encodeCursor(seq: number): string {
  return Buffer.from(`cursor:${seq}`, 'utf8').toString('base64');
}

function decodeCursor(value: string): number {
  try {
    const text = Buffer.from(value, 'base64').toString('utf8');
    const match = text.match(/^cursor:(\d+)$/);
    return match === null ? 0 : parseInt(match[1], 10);
  } catch {
    return 0;
  }
}

// ---------------------------------------------------------------------------
// MCP: /mcp  (JSON-RPC 2.0, plain JSON, no SSE)
// ---------------------------------------------------------------------------

const MCP_VERSIONS = ['2026-07-28', '2026-03-26', '2025-06-18', '2025-03-26', '2024-11-05'];

const MCP_TOOLS: Array<Record<string, unknown>> = [
  {
    name: 'create_repo',
    description: 'Create a repository',
    inputSchema: { type: 'object', properties: { name: { type: 'string' }, description: { type: 'string' }, private: { type: 'boolean' } }, required: ['name'] },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name',
    inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, name: { type: 'string' } }, required: ['owner', 'repo'] },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository',
    inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, title: { type: 'string' }, body: { type: 'string' } }, required: ['owner', 'repo', 'title'] },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository',
    inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, state: { type: 'string' } }, required: ['owner', 'repo'] },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request',
    inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, title: { type: 'string' }, head: { type: 'string' }, base: { type: 'string' } }, required: ['owner', 'repo', 'title', 'head', 'base'] },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request (squash)',
    inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, pull_number: { type: 'number' } }, required: ['owner', 'repo', 'pull_number'] },
  },
  {
    name: 'get_issue',
    description: 'Get one issue by number',
    inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, issue_number: { type: 'number' } }, required: ['owner', 'repo', 'issue_number'] },
  },
  {
    name: 'create_comment',
    description: 'Create a comment on an issue',
    inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, issue_number: { type: 'number' }, body: { type: 'string' } }, required: ['owner', 'repo', 'issue_number', 'body'] },
  },
];

function mcpResult(id: unknown, result: unknown): Record<string, unknown> {
  return { jsonrpc: '2.0', id: id === undefined ? null : id, result };
}

function mcpError(id: unknown, code: number, message: string): Record<string, unknown> {
  return { jsonrpc: '2.0', id: id === undefined ? null : id, error: { code, message } };
}

function mcpToolObject(obj: unknown): Record<string, unknown> {
  return {
    content: [{ type: 'text', text: JSON.stringify(obj) }],
    structuredContent: obj,
    isError: false,
  };
}

function mcpToolError(message: string): Record<string, unknown> {
  return {
    content: [{ type: 'text', text: JSON.stringify({ error: message }) }],
    structuredContent: { error: message },
    isError: true,
  };
}

function mcpRepoName(args: Record<string, unknown>): string {
  if (typeof args.repo === 'string') return args.repo;
  if (typeof args.name === 'string') return args.name;
  return '';
}

function handleMcpToolsCall(id: unknown, params: Record<string, unknown>): Record<string, unknown> {
  const name = typeof params.name === 'string' ? params.name : '';
  const args: Record<string, unknown> = isRecord(params.arguments) ? params.arguments : {};

  if (!MCP_TOOLS.some((tool) => tool.name === name)) {
    return mcpError(id, -32602, `unknown tool ${name}`);
  }

  if (name === 'create_repo') {
    if (typeof args.name !== 'string' || args.name === '') {
      return mcpResult(id, mcpToolError('name is required'));
    }
    const existing = findRepo(VIEWER_LOGIN, args.name);
    if (existing !== null) return mcpResult(id, mcpToolObject(repoJson(existing)));
    const description = typeof args.description === 'string' ? args.description : '';
    const isPrivate = args.private === true;
    const repo = createRepoRecord(args.name, description, isPrivate, 'main');
    repos.set(repoKey(VIEWER_LOGIN, args.name), repo);
    return mcpResult(id, mcpToolObject(repoJson(repo)));
  }

  if (name === 'get_repo') {
    if (typeof args.owner !== 'string' || mcpRepoName(args) === '') {
      return mcpResult(id, mcpToolError('owner and repo are required'));
    }
    const repo = findRepo(args.owner, mcpRepoName(args));
    if (repo === null) return mcpResult(id, mcpToolError('repository not found'));
    return mcpResult(id, mcpToolObject(repoJson(repo)));
  }

  if (name === 'create_issue') {
    if (typeof args.owner !== 'string' || mcpRepoName(args) === '' || typeof args.title !== 'string') {
      return mcpResult(id, mcpToolError('owner, repo and title are required'));
    }
    const repo = findRepo(args.owner, mcpRepoName(args));
    if (repo === null) return mcpResult(id, mcpToolError('repository not found'));
    const num = repo.nextNumber++;
    const now = nextIso();
    const issue: Issue = {
      number: num,
      title: args.title,
      body: typeof args.body === 'string' ? args.body : '',
      state: 'open',
      labels: [],
      createdAt: now,
      updatedAt: now,
      closedAt: null,
      comments: [],
    };
    repo.issues.set(num, issue);
    return mcpResult(id, mcpToolObject(issueJson(repo, issue)));
  }

  if (name === 'list_issues') {
    if (typeof args.owner !== 'string' || mcpRepoName(args) === '') {
      return mcpResult(id, mcpToolError('owner and repo are required'));
    }
    const repo = findRepo(args.owner, mcpRepoName(args));
    if (repo === null) return mcpResult(id, mcpToolError('repository not found'));
    const state = typeof args.state === 'string' ? args.state : 'open';
    let list = [...repo.issues.values()];
    if (state !== 'all') list = list.filter((issue) => issue.state === state);
    list.sort((a, b) => a.number - b.number);
    const issues = list.map((issue) => issueJson(repo, issue));
    return mcpResult(id, mcpToolObject({ issues }));
  }

  if (name === 'create_pull_request') {
    if (typeof args.owner !== 'string' || mcpRepoName(args) === '' || typeof args.title !== 'string' || typeof args.head !== 'string' || typeof args.base !== 'string') {
      return mcpResult(id, mcpToolError('owner, repo, title, head and base are required'));
    }
    const repo = findRepo(args.owner, mcpRepoName(args));
    if (repo === null) return mcpResult(id, mcpToolError('repository not found'));
    const head = args.head.includes(':') ? (args.head.split(':').pop() as string) : args.head;
    const base = args.base.includes(':') ? (args.base.split(':').pop() as string) : args.base;
    const headSha = resolveCommitTip(repo.objects, repo.refs, head);
    const baseSha = resolveCommitTip(repo.objects, repo.refs, base);
    if (headSha === null) return mcpResult(id, mcpToolError(`head branch ${head} does not exist`));
    if (baseSha === null) return mcpResult(id, mcpToolError(`base branch ${base} does not exist`));
    const num = repo.nextNumber++;
    const now = nextIso();
    const pull: PullRequest = {
      number: num,
      title: args.title,
      body: typeof args.body === 'string' ? args.body : '',
      state: 'open',
      merged: false,
      mergedAt: null,
      mergeCommitSha: null,
      head,
      base,
      headSha,
      baseSha,
      createdAt: now,
      updatedAt: now,
    };
    repo.pulls.set(num, pull);
    return mcpResult(id, mcpToolObject(pullJson(repo, pull)));
  }

  if (name === 'merge_pull_request') {
    if (typeof args.owner !== 'string' || mcpRepoName(args) === '' || typeof args.pull_number !== 'number') {
      return mcpResult(id, mcpToolError('owner, repo and pull_number are required'));
    }
    const repo = findRepo(args.owner, mcpRepoName(args));
    if (repo === null) return mcpResult(id, mcpToolError('repository not found'));
    const pull = repo.pulls.get(args.pull_number);
    if (pull === undefined) return mcpResult(id, mcpToolError('pull request not found'));
    if (pull.merged) return mcpResult(id, mcpToolObject({ merged: true, sha: pull.mergeCommitSha }));
    if (prConflicts(repo, pull)) return mcpResult(id, mcpToolError('merge conflict'));
    const sha = squashMerge(repo, pull);
    return mcpResult(id, mcpToolObject({ merged: true, sha }));
  }

  if (name === 'get_issue') {
    if (typeof args.owner !== 'string' || mcpRepoName(args) === '' || typeof args.issue_number !== 'number') {
      return mcpResult(id, mcpToolError('owner, repo and issue_number are required'));
    }
    const repo = findRepo(args.owner, mcpRepoName(args));
    if (repo === null) return mcpResult(id, mcpToolError('repository not found'));
    const issue = repo.issues.get(args.issue_number);
    if (issue === undefined) return mcpResult(id, mcpToolError('issue not found'));
    return mcpResult(id, mcpToolObject(issueJson(repo, issue)));
  }

  if (name === 'create_comment') {
    if (typeof args.owner !== 'string' || mcpRepoName(args) === '' || typeof args.issue_number !== 'number' || typeof args.body !== 'string') {
      return mcpResult(id, mcpToolError('owner, repo, issue_number and body are required'));
    }
    const repo = findRepo(args.owner, mcpRepoName(args));
    if (repo === null) return mcpResult(id, mcpToolError('repository not found'));
    const issue = repo.issues.get(args.issue_number);
    if (issue === undefined) return mcpResult(id, mcpToolError('issue not found'));
    const comment = { id: repo.nextCommentId++, body: args.body, createdAt: nextIso() };
    issue.comments.push(comment);
    issue.updatedAt = nextIso();
    return mcpResult(id, mcpToolObject({ id: comment.id, body: comment.body, created_at: comment.createdAt, user: { login: VIEWER_LOGIN, id: VIEWER_ID } }));
  }

  return mcpError(id, -32602, `unknown tool ${name}`);
}

function negotiatedMcpVersion(offered: unknown): string {
  return typeof offered === 'string' && MCP_VERSIONS.includes(offered) ? offered : '2026-07-28';
}

async function handleMcp(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const text = await readBody(req);
  let payload: unknown;
  try {
    payload = JSON.parse(text);
  } catch {
    sendJson(res, 400, mcpError(null, -32700, 'parse error'));
    return;
  }
  if (!isRecord(payload) || typeof payload.method !== 'string') {
    sendJson(res, 400, mcpError(null, -32600, 'invalid request'));
    return;
  }
  const id = payload.id;
  const method = payload.method;
  const params: Record<string, unknown> = isRecord(payload.params) ? payload.params : {};
  const isNotification = id === undefined || id === null;

  if (method === 'server/discover') {
    sendJson(res, 200, mcpResult(id, {
      protocolVersion: negotiatedMcpVersion(params.protocolVersion),
      supportedVersions: MCP_VERSIONS,
      supported_versions: MCP_VERSIONS,
      capabilities: { tools: {} },
      serverInfo: { name: 'forge', version: '1.0.0' },
    }));
    return;
  }
  if (method === 'initialize') {
    sendJson(res, 200, mcpResult(id, {
      protocolVersion: negotiatedMcpVersion(params.protocolVersion),
      capabilities: { tools: {} },
      serverInfo: { name: 'forge', version: '1.0.0' },
    }));
    return;
  }
  if (method === 'notifications/initialized') {
    res.writeHead(202, { 'x-github-request-id': nextRequestId() });
    res.end();
    return;
  }
  if (method === 'ping') {
    sendJson(res, 200, mcpResult(id, {}));
    return;
  }
  if (method === 'tools/list') {
    sendJson(res, 200, mcpResult(id, { tools: MCP_TOOLS }));
    return;
  }
  if (method === 'tools/call') {
    sendJson(res, 200, handleMcpToolsCall(id, params));
    return;
  }
  if (isNotification) {
    res.writeHead(202, { 'x-github-request-id': nextRequestId() });
    res.end();
    return;
  }
  sendJson(res, 200, mcpError(id, -32601, `method not found: ${method}`));
}

// ---------------------------------------------------------------------------
// Router + server
// ---------------------------------------------------------------------------

async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  try {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    const pathname = url.pathname;
    const query = url.searchParams;

    if (req.method === 'GET' && pathname === '/healthz') {
      sendJson(res, 200, { ok: true });
      return;
    }
    if (!checkAuth(req)) {
      errorJson(res, 401, 'unauthorized');
      return;
    }
    if (pathname === '/api/graphql') {
      await handleGraphql(req, res);
      return;
    }
    if (pathname === '/mcp') {
      await handleMcp(req, res);
      return;
    }
    const segments = splitPath(pathname);
    if (segments.length >= 2 && segments[0] === 'api' && segments[1] === 'v3') {
      await handleRest(req, res, segments.slice(2), query);
      return;
    }
    if (segments.length >= 2 && segments[1].endsWith('.git')) {
      const owner = segments[0];
      const name = segments[1].slice(0, -4);
      await handleGit(req, res, owner, name, segments.slice(2), query);
      return;
    }
    errorJson(res, 404, 'unknown route');
  } catch (err) {
    const message = err instanceof Error ? err.message : 'internal error';
    if (!res.headersSent) {
      errorJson(res, 500, message);
    }
  }
}

export function buildServer(): Server {
  return createServer({ sendDate: false }, (req, res) => {
    void handleRequest(req, res);
  });
}
