const encoder = new TextEncoder();

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])]));
  }
  return value;
}

export function canonical(value) { return JSON.stringify(stable(value)); }

function base64url(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64url(value) {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
  return Uint8Array.from(atob(padded), char => char.charCodeAt(0));
}

export async function fingerprint(publicKey) {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(canonical(publicKey)));
  return base64url(new Uint8Array(digest));
}

export async function createIdentity(label) {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const publicKey = await crypto.subtle.exportKey('jwk', pair.publicKey);
  return { label, privateKey: pair.privateKey, publicKey, keyId: await fingerprint(publicKey) };
}

export async function signClaim(issuer, payload) {
  const bytes = encoder.encode(canonical(payload));
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, issuer.privateKey, bytes);
  return { payload, signature: base64url(new Uint8Array(signature)) };
}

export function createChallenge(audience, requestScope, now = Date.now()) {
  const nonce = base64url(crypto.getRandomValues(new Uint8Array(16)));
  return { nonce, audience, requestScope, issuedAt: now };
}

export async function signChallenge(identity, challenge) {
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, identity.privateKey, encoder.encode(canonical(challenge))
  );
  return base64url(new Uint8Array(signature));
}

async function verifyPossession(publicKey, challenge, signature) {
  if (!challenge || typeof signature !== 'string') return false;
  try {
    const key = await crypto.subtle.importKey('jwk', publicKey, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' }, key, fromBase64url(signature), encoder.encode(canonical(challenge))
    );
  } catch { return false; }
}

export async function verifyClaim(claim, pinnedIssuerKey) {
  if (!claim?.payload || typeof claim.signature !== 'string' || !pinnedIssuerKey) return false;
  try {
    const key = await crypto.subtle.importKey('jwk', pinnedIssuerKey, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' }, key, fromBase64url(claim.signature), encoder.encode(canonical(claim.payload))
    );
  } catch { return false; }
}

function result(decision, code, detail, checks) { return { decision, code, detail, checks }; }

const challengeWindowMs = 60_000;

export function createVerifier() {
  const challenges = new Map();
  return {
    issue(audience, scope, now = Date.now()) {
      for (const [nonce, entry] of challenges) {
        if (entry.challenge.issuedAt + challengeWindowMs < now) challenges.delete(nonce);
      }
      const challenge = createChallenge(audience, scope, now);
      challenges.set(challenge.nonce, { challenge: { ...challenge }, used: false });
      return challenge;
    },
    assess: input => assessTask(input, challenges)
  };
}

async function assessTask(input, challenges) {
  const { agentId, agentPublicKey, requestScope, audience, claims, anchors, revokedIds = [], now, challenge, proofSignature } = input;
  const checks = [];
  const issued = challenges.get(challenge?.nonce);
  if (!issued || canonical(issued.challenge) !== canonical(challenge) ||
      challenge.audience !== audience || challenge.requestScope !== requestScope ||
      !Number.isFinite(now) || now < challenge.issuedAt || now - challenge.issuedAt > challengeWindowMs ||
      !await verifyPossession(agentPublicKey, challenge, proofSignature)) {
    return result('REFUSE', 'CHALLENGE_INVALID', 'The presenter did not prove possession of this key for the current task challenge.', checks);
  }
  // Claim before the next await so concurrent presentations cannot both succeed.
  if (issued.used) return result('REFUSE', 'CHALLENGE_REPLAY', 'This signed challenge was already used.', checks);
  issued.used = true;
  checks.push('Fresh, single-use task challenge: private key possession verified');
  const subjectKey = await fingerprint(agentPublicKey);
  const byType = type => claims.find(claim => claim?.payload?.type === type);
  const capability = byType('capability');
  const history = byType('action-receipt');
  const vouch = byType('vouch');
  if (!capability || !history || !vouch) return result('REFUSE', 'PROOF_MISSING', 'Capability, signed action receipt, and independent vouch are all required.', checks);

  for (const [label, claim, issuer] of [
    ['Capability', capability, anchors.organization],
    ['Action receipt', history, anchors.organization],
    ['Independent vouch', vouch, anchors.peer]
  ]) {
    if (!await verifyClaim(claim, issuer)) return result('REFUSE', 'SIGNATURE_INVALID', `${label} does not verify against its pinned issuer key.`, checks);
    checks.push(`${label}: signature verified`);
    const body = claim.payload;
    if (body.subject !== agentId || body.subjectKey !== subjectKey) return result('REFUSE', 'IDENTITY_MISMATCH', `${label} is bound to a different agent identity or key.`, checks);
    checks.push(`${label}: subject key bound`);
    if (revokedIds.includes(body.id)) return result('REFUSE', 'REVOKED', `${label} was revoked.`, checks);
    if (!Number.isFinite(body.expiresAt) || body.expiresAt <= now || body.issuedAt > now) return result('REFUSE', 'EXPIRED', `${label} is outside its validity window.`, checks);
  }

  if (capability.payload.audience !== audience) return result('REFUSE', 'WRONG_AUDIENCE', 'Capability is scoped to a different verifier.', checks);
  checks.push('Audience: bound to this verifier');
  if (!Array.isArray(capability.payload.scopes) || !capability.payload.scopes.includes(requestScope)) {
    return result('REFUSE', 'OUT_OF_SCOPE', `The requested ${requestScope} action is outside the signed authority.`, checks);
  }
  checks.push(`Authority: ${requestScope} granted`);
  return result('ACCEPT', 'TRUST_VERIFIED', 'Pinned issuers, identity binding, validity, revocation, reputation evidence, and task scope all passed.', checks);
}

export async function createSyntheticNetwork(now = Date.now()) {
  const [organization, peer, agent, impostor] = await Promise.all([
    createIdentity('Northstar Operations'), createIdentity('Harbor Partner'),
    createIdentity('Courier-7'), createIdentity('Unknown agent')
  ]);
  const common = { subject: 'agent:courier-7', subjectKey: agent.keyId, issuedAt: now - 60_000, expiresAt: now + 86_400_000 };
  const claims = [
    await signClaim(organization, { ...common, id: 'cap-104', type: 'capability', audience: 'agent:warehouse', scopes: ['inventory:read'] }),
    await signClaim(organization, { ...common, id: 'run-728', type: 'action-receipt', outcome: 'fulfilled', action: 'inventory lookup' }),
    await signClaim(peer, { ...common, id: 'vouch-22', type: 'vouch', relationship: 'completed joint inventory handoff' })
  ];
  return { organization, peer, agent, impostor, claims, now };
}
