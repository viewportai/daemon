import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { configDir } from '../core/config.js';

export interface PairingOfferConnection {
  host: string;
  port: number;
  listen: string;
  socketPath?: string;
  profile: 'local' | 'lan' | 'relay';
}

interface PairingOfferStoreRecord {
  offerId: string;
  createdAt: number;
  expiresAt: number;
  revokedAt?: number;
  redeemedAt?: number;
  failedRedeemAttempts?: number;
  lockedAt?: number;
  redeemSecretHash: string;
  token: string;
  trustAnchor: string;
  daemonDeviceId: string;
  daemonPublicKey: string;
  connection: PairingOfferConnection;
}

interface PairingOfferStore {
  version: 1;
  offers: PairingOfferStoreRecord[];
}

export interface PairingOfferPublicPayload extends PairingOfferConnection {
  offerId: string;
  createdAt: number;
  expiresAt: number;
  trustAnchor: string;
  daemonDeviceId: string;
}

export interface PairingOfferIssuedPayload extends PairingOfferPublicPayload {
  redeemSecret: string;
  daemonPublicKey: string;
}

export interface PairingOfferRedeemedPayload {
  offerId: string;
  token: string;
  trustAnchor: string;
  daemonDeviceId: string;
  daemonPublicKey: string;
  peerId: string;
  serverSignature: string;
  connection: PairingOfferConnection;
  expiresAt: number;
  createdAt: number;
}

interface PairingTrustAnchorRecord {
  version: 1;
  id: string;
  createdAt: number;
  secret: string;
}

export interface PairingTrustAnchorPublic {
  id: string;
  createdAt: number;
  fingerprint: string;
}

interface PairingDaemonIdentityRecord {
  version: 1;
  deviceId: string;
  createdAt: number;
  publicKey: string;
  privateKey: string;
}

interface PairingPeerBindingRecord {
  peerId: string;
  publicKey: string;
  firstPairedAt: number;
  lastPairedAt: number;
  lastOfferId: string;
  trustAnchor: string;
}

interface PairingPeerBindingStore {
  version: 1;
  peers: PairingPeerBindingRecord[];
}

export interface PairingDaemonIdentityPublic {
  deviceId: string;
  createdAt: number;
  fingerprint: string;
  publicKey: string;
}

export interface PairingClientIdentity {
  peerId: string;
  publicKey: string;
  privateKey: string;
}

export interface PairingRedeemProof {
  peerId: string;
  clientPublicKey: string;
  clientProof: string;
}

const MAX_STORED_OFFERS = 200;
const MAX_FAILED_REDEEM_ATTEMPTS = 5;

function pairingStorePath(): string {
  return path.join(configDir(), 'pairing-offers.json');
}

function pairingAuditPath(): string {
  return path.join(configDir(), 'pairing-audit.jsonl');
}

function authTokenPath(): string {
  return path.join(configDir(), 'auth-token');
}

function trustAnchorPath(): string {
  return path.join(configDir(), 'pairing-trust-anchor.json');
}

function daemonIdentityPath(): string {
  return path.join(configDir(), 'pairing-device-identity.json');
}

function peerBindingPath(): string {
  return path.join(configDir(), 'pairing-peers.json');
}

async function readStore(): Promise<PairingOfferStore> {
  try {
    const raw = await fs.readFile(pairingStorePath(), 'utf-8');
    const parsed = JSON.parse(raw) as PairingOfferStore;
    if (!Array.isArray(parsed.offers)) {
      return { version: 1, offers: [] };
    }
    return {
      version: 1,
      offers: parsed.offers.filter((item) => item && typeof item.offerId === 'string'),
    };
  } catch {
    return { version: 1, offers: [] };
  }
}

async function writeStore(store: PairingOfferStore): Promise<void> {
  await fs.mkdir(configDir(), { recursive: true });
  const compacted = compactOffers(store.offers);
  await fs.writeFile(
    pairingStorePath(),
    JSON.stringify({ version: 1, offers: compacted }, null, 2) + '\n',
    'utf-8',
  );
}

function compactOffers(offers: PairingOfferStoreRecord[]): PairingOfferStoreRecord[] {
  const now = Date.now();
  const fresh = offers.filter((offer) => {
    if (!offer.expiresAt || offer.expiresAt <= now - 24 * 60 * 60 * 1000) {
      return false;
    }
    return true;
  });
  if (fresh.length <= MAX_STORED_OFFERS) return fresh;
  return fresh.slice(fresh.length - MAX_STORED_OFFERS);
}

async function appendAudit(event: Record<string, unknown>): Promise<void> {
  await fs.mkdir(configDir(), { recursive: true });
  const line = JSON.stringify({ timestamp: Date.now(), ...event });
  await fs.appendFile(pairingAuditPath(), `${line}\n`, 'utf-8');
}

function trustAnchorFingerprint(secret: string): string {
  const digest = crypto.createHash('sha256').update(secret).digest('hex');
  return digest.match(/.{1,4}/g)?.join(':') ?? digest;
}

function keyFingerprint(publicKey: string): string {
  const digest = crypto.createHash('sha256').update(publicKey).digest('hex');
  return digest.match(/.{1,4}/g)?.join(':') ?? digest;
}

async function readTrustAnchorRecord(): Promise<PairingTrustAnchorRecord | null> {
  try {
    const raw = await fs.readFile(trustAnchorPath(), 'utf-8');
    const parsed = JSON.parse(raw) as PairingTrustAnchorRecord;
    if (
      parsed &&
      parsed.version === 1 &&
      typeof parsed.id === 'string' &&
      typeof parsed.createdAt === 'number' &&
      typeof parsed.secret === 'string' &&
      parsed.secret.length > 0
    ) {
      return parsed;
    }
    return null;
  } catch {
    return null;
  }
}

async function writeTrustAnchorRecord(record: PairingTrustAnchorRecord): Promise<void> {
  await fs.mkdir(configDir(), { recursive: true });
  await fs.writeFile(trustAnchorPath(), JSON.stringify(record, null, 2) + '\n', {
    mode: 0o600,
  });
}

export async function getOrCreateTrustAnchor(): Promise<PairingTrustAnchorPublic> {
  const existing = await readTrustAnchorRecord();
  if (existing) {
    return {
      id: existing.id,
      createdAt: existing.createdAt,
      fingerprint: trustAnchorFingerprint(existing.secret),
    };
  }
  const created: PairingTrustAnchorRecord = {
    version: 1,
    id: crypto.randomUUID(),
    createdAt: Date.now(),
    secret: crypto.randomBytes(32).toString('hex'),
  };
  await writeTrustAnchorRecord(created);
  await appendAudit({
    event: 'pair_trust_anchor_created',
    trustAnchorId: created.id,
    trustAnchor: trustAnchorFingerprint(created.secret),
  });
  return {
    id: created.id,
    createdAt: created.createdAt,
    fingerprint: trustAnchorFingerprint(created.secret),
  };
}

async function readDaemonIdentity(): Promise<PairingDaemonIdentityRecord | null> {
  try {
    const raw = await fs.readFile(daemonIdentityPath(), 'utf-8');
    const parsed = JSON.parse(raw) as PairingDaemonIdentityRecord;
    if (
      parsed &&
      parsed.version === 1 &&
      typeof parsed.deviceId === 'string' &&
      typeof parsed.createdAt === 'number' &&
      typeof parsed.publicKey === 'string' &&
      typeof parsed.privateKey === 'string'
    ) {
      return parsed;
    }
    return null;
  } catch {
    return null;
  }
}

async function writeDaemonIdentity(identity: PairingDaemonIdentityRecord): Promise<void> {
  await fs.mkdir(configDir(), { recursive: true });
  await fs.writeFile(daemonIdentityPath(), JSON.stringify(identity, null, 2) + '\n', {
    mode: 0o600,
  });
}

export async function getOrCreateDaemonIdentity(): Promise<PairingDaemonIdentityPublic> {
  const existing = await readDaemonIdentity();
  if (existing) {
    return {
      deviceId: existing.deviceId,
      createdAt: existing.createdAt,
      fingerprint: keyFingerprint(existing.publicKey),
      publicKey: existing.publicKey,
    };
  }
  const keypair = crypto.generateKeyPairSync('ed25519');
  const publicKey = keypair.publicKey.export({ type: 'spki', format: 'pem' }).toString().trim();
  const privateKey = keypair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString().trim();
  const created: PairingDaemonIdentityRecord = {
    version: 1,
    deviceId: crypto.randomUUID(),
    createdAt: Date.now(),
    publicKey,
    privateKey,
  };
  await writeDaemonIdentity(created);
  await appendAudit({
    event: 'pair_device_identity_created',
    deviceId: created.deviceId,
    fingerprint: keyFingerprint(created.publicKey),
  });
  return {
    deviceId: created.deviceId,
    createdAt: created.createdAt,
    fingerprint: keyFingerprint(created.publicKey),
    publicKey: created.publicKey,
  };
}

function canonicalRedeemPayload(input: {
  offerId: string;
  redeemSecret: string;
  trustAnchor: string;
  clientPublicKey: string;
}): string {
  return [
    'viewport-pair-redeem-v1',
    input.offerId,
    input.redeemSecret,
    input.trustAnchor,
    input.clientPublicKey,
  ].join('\n');
}

function peerIdFromPublicKey(publicKey: string): string {
  return crypto.createHash('sha256').update(publicKey).digest('hex');
}

async function readPeerBindings(): Promise<PairingPeerBindingStore> {
  try {
    const raw = await fs.readFile(peerBindingPath(), 'utf-8');
    const parsed = JSON.parse(raw) as PairingPeerBindingStore;
    if (!parsed || parsed.version !== 1 || !Array.isArray(parsed.peers)) {
      return { version: 1, peers: [] };
    }
    return {
      version: 1,
      peers: parsed.peers.filter(
        (item) =>
          item &&
          typeof item.peerId === 'string' &&
          typeof item.publicKey === 'string' &&
          typeof item.firstPairedAt === 'number',
      ),
    };
  } catch {
    return { version: 1, peers: [] };
  }
}

async function writePeerBindings(store: PairingPeerBindingStore): Promise<void> {
  await fs.mkdir(configDir(), { recursive: true });
  await fs.writeFile(peerBindingPath(), JSON.stringify(store, null, 2) + '\n', {
    mode: 0o600,
  });
}

async function upsertPeerBinding(input: {
  peerId: string;
  publicKey: string;
  offerId: string;
  trustAnchor: string;
}): Promise<void> {
  const store = await readPeerBindings();
  const now = Date.now();
  const existing = store.peers.find((peer) => peer.peerId === input.peerId);
  if (existing) {
    existing.publicKey = input.publicKey;
    existing.lastPairedAt = now;
    existing.lastOfferId = input.offerId;
    existing.trustAnchor = input.trustAnchor;
  } else {
    store.peers.push({
      peerId: input.peerId,
      publicKey: input.publicKey,
      firstPairedAt: now,
      lastPairedAt: now,
      lastOfferId: input.offerId,
      trustAnchor: input.trustAnchor,
    });
  }
  await writePeerBindings(store);
}

export function createPairingClientIdentity(): PairingClientIdentity {
  const keypair = crypto.generateKeyPairSync('ed25519');
  const publicKey = keypair.publicKey.export({ type: 'spki', format: 'pem' }).toString().trim();
  const privateKey = keypair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString().trim();
  return {
    peerId: peerIdFromPublicKey(publicKey),
    publicKey,
    privateKey,
  };
}

export function createPairingRedeemProof(input: {
  offerId: string;
  redeemSecret: string;
  trustAnchor: string;
  clientIdentity: PairingClientIdentity;
}): PairingRedeemProof {
  const normalizedClientPublicKey = input.clientIdentity.publicKey.trim();
  const normalizedClientPrivateKey = input.clientIdentity.privateKey.trim();
  const payload = canonicalRedeemPayload({
    offerId: input.offerId,
    redeemSecret: input.redeemSecret,
    trustAnchor: input.trustAnchor,
    clientPublicKey: normalizedClientPublicKey,
  });
  const signature = crypto.sign(
    null,
    Buffer.from(payload, 'utf-8'),
    crypto.createPrivateKey(normalizedClientPrivateKey),
  );
  return {
    peerId: peerIdFromPublicKey(normalizedClientPublicKey),
    clientPublicKey: normalizedClientPublicKey,
    clientProof: signature.toString('base64url'),
  };
}

export async function readAuthToken(): Promise<string | null> {
  try {
    const token = (await fs.readFile(authTokenPath(), 'utf-8')).trim();
    return token || null;
  } catch {
    return null;
  }
}

export async function rotateAuthToken(): Promise<{ token: string; previousTokenExisted: boolean }> {
  const previous = await readAuthToken();
  const token = crypto.randomBytes(32).toString('hex');
  await fs.mkdir(configDir(), { recursive: true });
  await fs.writeFile(authTokenPath(), `${token}\n`, { mode: 0o600 });
  await appendAudit({ event: 'auth_token_rotated' });
  return { token, previousTokenExisted: previous !== null };
}

export async function issuePairingOffer(input: {
  connection: PairingOfferConnection;
  ttlSeconds: number;
}): Promise<PairingOfferIssuedPayload> {
  const ttlSeconds = Math.min(3600, Math.max(30, Math.floor(input.ttlSeconds)));
  const createdAt = Date.now();
  const expiresAt = createdAt + ttlSeconds * 1000;
  const offerId = crypto.randomUUID();
  const redeemSecret = crypto.randomBytes(16).toString('hex');
  const token = await readAuthToken();
  if (!token) {
    throw new Error('No auth token available for pairing offer');
  }
  const trustAnchor = await getOrCreateTrustAnchor();
  const daemonIdentity = await getOrCreateDaemonIdentity();

  const store = await readStore();
  store.offers.push({
    offerId,
    createdAt,
    expiresAt,
    redeemSecretHash: hashSecret(redeemSecret),
    token,
    trustAnchor: trustAnchor.fingerprint,
    daemonDeviceId: daemonIdentity.deviceId,
    daemonPublicKey: daemonIdentity.publicKey,
    connection: input.connection,
  });
  await writeStore(store);
  await appendAudit({
    event: 'pair_offer_issued',
    offerId,
    createdAt,
    expiresAt,
    profile: input.connection.profile,
    listen: input.connection.listen,
    trustAnchor: trustAnchor.fingerprint,
    daemonDeviceId: daemonIdentity.deviceId,
  });

  return {
    offerId,
    createdAt,
    expiresAt,
    redeemSecret,
    trustAnchor: trustAnchor.fingerprint,
    daemonDeviceId: daemonIdentity.deviceId,
    daemonPublicKey: daemonIdentity.publicKey,
    ...input.connection,
  };
}

export async function listPairingOffers(): Promise<
  Array<
    PairingOfferPublicPayload & {
      revokedAt?: number;
      redeemedAt?: number;
      active: boolean;
      expired: boolean;
    }
  >
> {
  const store = await readStore();
  const now = Date.now();
  return store.offers
    .map((offer) => {
      const expired = offer.expiresAt <= now;
      const active = !expired && !offer.revokedAt && !offer.redeemedAt;
      return {
        offerId: offer.offerId,
        createdAt: offer.createdAt,
        expiresAt: offer.expiresAt,
        trustAnchor: offer.trustAnchor,
        daemonDeviceId: offer.daemonDeviceId,
        host: offer.connection.host,
        port: offer.connection.port,
        listen: offer.connection.listen,
        socketPath: offer.connection.socketPath,
        profile: offer.connection.profile,
        revokedAt: offer.revokedAt,
        redeemedAt: offer.redeemedAt,
        active,
        expired,
      };
    })
    .sort((a, b) => b.createdAt - a.createdAt);
}

export async function revokePairingOffer(offerId: string): Promise<boolean> {
  const store = await readStore();
  const offer = store.offers.find((item) => item.offerId === offerId);
  if (!offer) return false;
  if (!offer.revokedAt) {
    offer.revokedAt = Date.now();
    await writeStore(store);
    await appendAudit({ event: 'pair_offer_revoked', offerId: offer.offerId });
  }
  return true;
}

export async function redeemPairingOffer(
  offerId: string,
  redeemSecret: string,
  expectedTrustAnchor?: string,
  clientPublicKey?: string,
  clientProof?: string,
): Promise<PairingOfferRedeemedPayload | null> {
  if (!redeemSecret || redeemSecret.trim().length === 0) {
    return null;
  }

  const store = await readStore();
  const offer = store.offers.find((item) => item.offerId === offerId);
  if (!offer) return null;

  const now = Date.now();
  const expired = offer.expiresAt <= now;
  if (expired || offer.revokedAt || offer.redeemedAt || offer.lockedAt) {
    return null;
  }
  if (!clientPublicKey || !clientProof) {
    await appendAudit({
      event: 'pair_offer_redeem_failed',
      offerId: offer.offerId,
      reason: 'missing_client_identity_proof',
    });
    return null;
  }
  if (expectedTrustAnchor && offer.trustAnchor !== expectedTrustAnchor) {
    await appendAudit({
      event: 'pair_offer_redeem_failed',
      offerId: offer.offerId,
      reason: 'trust_anchor_mismatch',
      expectedTrustAnchor,
      offeredTrustAnchor: offer.trustAnchor,
    });
    return null;
  }
  try {
    const payload = canonicalRedeemPayload({
      offerId: offer.offerId,
      redeemSecret,
      trustAnchor: offer.trustAnchor,
      clientPublicKey,
    });
    const verified = crypto.verify(
      null,
      Buffer.from(payload, 'utf-8'),
      crypto.createPublicKey(clientPublicKey),
      Buffer.from(clientProof, 'base64url'),
    );
    if (!verified) {
      await appendAudit({
        event: 'pair_offer_redeem_failed',
        offerId: offer.offerId,
        reason: 'client_proof_invalid',
      });
      return null;
    }
  } catch {
    await appendAudit({
      event: 'pair_offer_redeem_failed',
      offerId: offer.offerId,
      reason: 'client_proof_invalid',
    });
    return null;
  }
  if (typeof offer.redeemSecretHash !== 'string' || offer.redeemSecretHash.length === 0) {
    offer.lockedAt = now;
    await writeStore(store);
    await appendAudit({
      event: 'pair_offer_redeem_failed',
      offerId: offer.offerId,
      reason: 'missing_redeem_secret_hash',
    });
    return null;
  }

  const proofValid = secureSecretCompare(offer.redeemSecretHash, hashSecret(redeemSecret));
  if (!proofValid) {
    offer.failedRedeemAttempts = (offer.failedRedeemAttempts ?? 0) + 1;
    if (offer.failedRedeemAttempts >= MAX_FAILED_REDEEM_ATTEMPTS) {
      offer.lockedAt = now;
    }
    await writeStore(store);
    await appendAudit({
      event: 'pair_offer_redeem_failed',
      offerId: offer.offerId,
      attempts: offer.failedRedeemAttempts,
      locked: !!offer.lockedAt,
    });
    return null;
  }

  offer.redeemedAt = now;
  await writeStore(store);
  const peerId = peerIdFromPublicKey(clientPublicKey);
  await upsertPeerBinding({
    peerId,
    publicKey: clientPublicKey,
    offerId: offer.offerId,
    trustAnchor: offer.trustAnchor,
  });

  const daemonIdentity = await readDaemonIdentity();
  const daemonPrivateKey = daemonIdentity
    ? crypto.createPrivateKey(daemonIdentity.privateKey)
    : undefined;
  const redeemEnvelope = [
    'viewport-pair-redeem-response-v1',
    offer.offerId,
    peerId,
    offer.trustAnchor,
    String(offer.expiresAt),
  ].join('\n');
  const serverSignature = daemonPrivateKey
    ? crypto
        .sign(null, Buffer.from(redeemEnvelope, 'utf-8'), daemonPrivateKey)
        .toString('base64url')
    : '';

  await appendAudit({
    event: 'pair_offer_redeemed',
    offerId: offer.offerId,
    peerId,
    daemonDeviceId: offer.daemonDeviceId,
  });

  return {
    offerId: offer.offerId,
    token: offer.token,
    trustAnchor: offer.trustAnchor,
    daemonDeviceId: offer.daemonDeviceId,
    daemonPublicKey: offer.daemonPublicKey,
    peerId,
    serverSignature,
    connection: offer.connection,
    expiresAt: offer.expiresAt,
    createdAt: offer.createdAt,
  };
}

function hashSecret(secret: string): string {
  return crypto.createHash('sha256').update(secret).digest('hex');
}

function secureSecretCompare(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf-8');
  const right = Buffer.from(b, 'utf-8');
  const compareLength = Math.max(left.length, right.length, 1);
  const paddedLeft = Buffer.alloc(compareLength);
  const paddedRight = Buffer.alloc(compareLength);
  left.copy(paddedLeft);
  right.copy(paddedRight);
  const equal = crypto.timingSafeEqual(paddedLeft, paddedRight);
  return equal && left.length === right.length;
}
