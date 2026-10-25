// SR-12: the public bulletin board. Read-only and unauthenticated on purpose:
// anyone holding a receipt can check it, and the board holds nothing that
// identifies a voter or shows a choice. Mounted in app.js.
const express = require('express');
const { lookupReceipt, getBoard } = require('../services/receipts');
const { getPublicKeyPem, getKeyId } = require('../security/receiptSigning');

function createBulletinBoardRouter({ db } = {}) {
  if (!db || typeof db.query !== 'function') {
    throw new TypeError('A database runner is required');
  }
  const router = express.Router();
  router.use('/api/bulletin-board', (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  });

  // The key anyone can use to verify a receipt signature offline
  router.get('/api/bulletin-board/public-key', (req, res, next) => {
    try {
      res.json({ keyId: getKeyId(), algorithm: 'Ed25519', publicKeyPem: getPublicKeyPem() });
    } catch (err) {
      next(err);
    }
  });

  router.get('/api/bulletin-board/elections/:electionId', async (req, res, next) => {
    if (!/^[1-9]\d{0,9}$/.test(req.params.electionId)) {
      return res.status(400).json({ error: 'Invalid election.' });
    }
    try {
      res.json(await getBoard(db, Number(req.params.electionId)));
    } catch (err) {
      next(err);
    }
  });

  // POST so the verification code is never placed in a URL (logs, history)
  router.post('/api/bulletin-board/verify', async (req, res, next) => {
    const receipt = req.body && req.body.receipt;
    if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) {
      return res.status(400).json({ error: 'A receipt is required.' });
    }
    try {
      res.json(await lookupReceipt(db, receipt));
    } catch (err) {
      next(err);
    }
  });

  return router;
}

module.exports = { createBulletinBoardRouter };
