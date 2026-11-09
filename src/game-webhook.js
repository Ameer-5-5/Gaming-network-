import { createHmac, timingSafeEqual } from 'node:crypto';

export function verifyGameWebhookSignature(rawBody, signature, secret) {
  if (!Buffer.isBuffer(rawBody) || typeof signature !== 'string' || typeof secret !== 'string' || !secret) {
    return false;
  }

  const match = /^sha256=([a-f0-9]{64})$/i.exec(signature);
  if (!match) {
    return false;
  }

  const expected = createHmac('sha256', secret).update(rawBody).digest();
  const supplied = Buffer.from(match[1], 'hex');
  return timingSafeEqual(expected, supplied);
}

export function createGameWebhookHandler({ secret, updateSessionState }) {
  if (typeof secret !== 'string' || !secret) {
    throw new TypeError('A non-empty webhook secret is required');
  }
  if (typeof updateSessionState !== 'function') {
    throw new TypeError('A session state updater is required');
  }

  return async function handleGameWebhook({ rawBody, signature }) {
    if (!verifyGameWebhookSignature(rawBody, signature, secret)) {
      const error = new Error('Invalid webhook signature');
      error.statusCode = 401;
      throw error;
    }

    let payload;
    try {
      payload = JSON.parse(rawBody.toString('utf8'));
    } catch {
      const error = new Error('Invalid JSON payload');
      error.statusCode = 400;
      throw error;
    }

    return updateSessionState(payload);
  };
}