import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  createPairingClientIdentity,
  createPairingRedeemProof,
  issuePairingOffer,
  listPairingOffers,
  redeemPairingOffer,
  revokePairingOffer,
  rotateAuthToken,
} from '../../src/server/pairing-offers.js';

describe('pairing offers', () => {
  let tempHome = '';
  const originalHome = process.env['HOME'];
  const originalViewportHome = process.env['VIEWPORT_HOME'];

  beforeEach(async () => {
    tempHome = await fs.mkdtemp(path.join(os.tmpdir(), 'viewport-pairing-test-'));
    process.env['HOME'] = tempHome;
    process.env['VIEWPORT_HOME'] = path.join(tempHome, '.viewport');
    await rotateAuthToken();
  });

  afterEach(async () => {
    if (originalHome) process.env['HOME'] = originalHome;
    else delete process.env['HOME'];
    if (originalViewportHome) process.env['VIEWPORT_HOME'] = originalViewportHome;
    else delete process.env['VIEWPORT_HOME'];
    await fs.rm(tempHome, { recursive: true, force: true });
  });

  it('issues, lists, redeems, and invalidates a pairing offer', async () => {
    const offer = await issuePairingOffer({
      connection: {
        host: '127.0.0.1',
        port: 7070,
        listen: '127.0.0.1:7070',
        profile: 'local',
      },
      ttlSeconds: 300,
    });

    const listed = await listPairingOffers();
    expect(listed.some((item) => item.offerId === offer.offerId && item.active)).toBe(true);
    expect(offer.redeemSecret).toBeTruthy();
    expect(offer.trustAnchor).toBeTruthy();
    expect(offer.daemonDeviceId).toBeTruthy();
    expect(offer.daemonPublicKey).toContain('BEGIN PUBLIC KEY');

    const identity = createPairingClientIdentity();
    const redeemProof = createPairingRedeemProof({
      offerId: offer.offerId,
      redeemSecret: offer.redeemSecret,
      trustAnchor: offer.trustAnchor,
      clientIdentity: identity,
    });

    const firstRedeem = await redeemPairingOffer(
      offer.offerId,
      offer.redeemSecret,
      offer.trustAnchor,
      redeemProof.clientPublicKey,
      redeemProof.clientProof,
    );
    expect(firstRedeem?.offerId).toBe(offer.offerId);
    expect(firstRedeem?.token).toBeTruthy();
    expect(firstRedeem?.trustAnchor).toBe(offer.trustAnchor);
    expect(firstRedeem?.daemonDeviceId).toBe(offer.daemonDeviceId);
    expect(firstRedeem?.daemonPublicKey).toBe(offer.daemonPublicKey);
    expect(firstRedeem?.peerId).toBe(identity.peerId);
    expect(firstRedeem?.serverSignature).toBeTruthy();

    const secondRedeem = await redeemPairingOffer(
      offer.offerId,
      offer.redeemSecret,
      offer.trustAnchor,
      redeemProof.clientPublicKey,
      redeemProof.clientProof,
    );
    expect(secondRedeem).toBeNull();
  });

  it('revokes an offer and prevents redemption', async () => {
    const offer = await issuePairingOffer({
      connection: {
        host: '127.0.0.1',
        port: 7070,
        listen: '127.0.0.1:7070',
        profile: 'local',
      },
      ttlSeconds: 300,
    });

    const revoked = await revokePairingOffer(offer.offerId);
    expect(revoked).toBe(true);

    const identity = createPairingClientIdentity();
    const redeemProof = createPairingRedeemProof({
      offerId: offer.offerId,
      redeemSecret: offer.redeemSecret,
      trustAnchor: offer.trustAnchor,
      clientIdentity: identity,
    });
    const redeemed = await redeemPairingOffer(
      offer.offerId,
      offer.redeemSecret,
      offer.trustAnchor,
      redeemProof.clientPublicKey,
      redeemProof.clientProof,
    );
    expect(redeemed).toBeNull();
  });

  it('locks a pairing offer after repeated invalid proof attempts', async () => {
    const offer = await issuePairingOffer({
      connection: {
        host: '127.0.0.1',
        port: 7070,
        listen: '127.0.0.1:7070',
        profile: 'local',
      },
      ttlSeconds: 300,
    });

    const identity = createPairingClientIdentity();

    for (let i = 0; i < 5; i += 1) {
      const wrongProof = createPairingRedeemProof({
        offerId: offer.offerId,
        redeemSecret: 'wrong-proof',
        trustAnchor: offer.trustAnchor,
        clientIdentity: identity,
      });
      const failed = await redeemPairingOffer(
        offer.offerId,
        'wrong-proof',
        offer.trustAnchor,
        wrongProof.clientPublicKey,
        wrongProof.clientProof,
      );
      expect(failed).toBeNull();
    }

    const redeemProof = createPairingRedeemProof({
      offerId: offer.offerId,
      redeemSecret: offer.redeemSecret,
      trustAnchor: offer.trustAnchor,
      clientIdentity: identity,
    });
    const lockedRedeem = await redeemPairingOffer(
      offer.offerId,
      offer.redeemSecret,
      offer.trustAnchor,
      redeemProof.clientPublicKey,
      redeemProof.clientProof,
    );
    expect(lockedRedeem).toBeNull();
  });

  it('rejects redemption when trust anchor does not match', async () => {
    const offer = await issuePairingOffer({
      connection: {
        host: '127.0.0.1',
        port: 7070,
        listen: '127.0.0.1:7070',
        profile: 'local',
      },
      ttlSeconds: 300,
    });

    const identity = createPairingClientIdentity();
    const redeemProof = createPairingRedeemProof({
      offerId: offer.offerId,
      redeemSecret: offer.redeemSecret,
      trustAnchor: offer.trustAnchor,
      clientIdentity: identity,
    });
    const redeemed = await redeemPairingOffer(
      offer.offerId,
      offer.redeemSecret,
      'dead:beef',
      redeemProof.clientPublicKey,
      redeemProof.clientProof,
    );
    expect(redeemed).toBeNull();
  });
});
