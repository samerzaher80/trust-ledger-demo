import test from 'node:test';
import assert from 'node:assert/strict';
import { createVerifier, createSyntheticNetwork, signChallenge } from '../trust.js';

const make = async () => {
  const network = await createSyntheticNetwork();
  const verifier = createVerifier();
  const input = {
    agentId: 'agent:courier-7', agentPublicKey: network.agent.publicKey,
    requestScope: 'inventory:read', audience: 'agent:warehouse', claims: network.claims,
    anchors: { organization: network.organization.publicKey, peer: network.peer.publicKey },
    now: network.now, revokedIds: [],
    challenge: verifier.issue('agent:warehouse', 'inventory:read', network.now)
  };
  input.proofSignature = await signChallenge(network.agent, input.challenge);
  return { network, input, verifier };
};

test('signed scope and independent reputation evidence allow the task', async () => {
  const { input, verifier } = await make();
  assert.equal((await verifier.assess(input)).decision, 'ACCEPT');
});
test('copied credentials fail when the presenting key changes', async () => {
  const { network, input, verifier } = await make();
  input.agentPublicKey = network.impostor.publicKey;
  input.proofSignature = await signChallenge(network.impostor, input.challenge);
  assert.equal((await verifier.assess(input)).code, 'IDENTITY_MISMATCH');
});
test('revoked authority fails even with a valid signature', async () => {
  const { input, verifier } = await make();
  input.revokedIds = ['cap-104'];
  assert.equal((await verifier.assess(input)).code, 'REVOKED');
});
test('task scope and audience cannot be widened', async () => {
  const { network, input, verifier } = await make();
  input.requestScope = 'payment:send';
  input.challenge = verifier.issue('agent:warehouse', input.requestScope, input.now);
  input.proofSignature = await signChallenge(network.agent, input.challenge);
  assert.equal((await verifier.assess(input)).code, 'OUT_OF_SCOPE');
  input.requestScope = 'inventory:read'; input.audience = 'agent:bank';
  input.challenge = verifier.issue(input.audience, input.requestScope, input.now);
  input.proofSignature = await signChallenge(network.agent, input.challenge);
  assert.equal((await verifier.assess(input)).code, 'WRONG_AUDIENCE');
});
test('tampering with a signed claim fails verification', async () => {
  const { input, verifier } = await make();
  input.claims = structuredClone(input.claims);
  input.claims[0].payload.scopes.push('payment:send');
  assert.equal((await verifier.assess(input)).code, 'SIGNATURE_INVALID');
});
test('expiry and missing independent vouch fail closed', async () => {
  const { network, input, verifier } = await make();
  input.now += 172_800_000;
  input.challenge = verifier.issue(input.audience, input.requestScope, input.now);
  input.proofSignature = await signChallenge(network.agent, input.challenge);
  assert.equal((await verifier.assess(input)).code, 'EXPIRED');
  input.now -= 172_800_000; input.challenge = verifier.issue('agent:warehouse', 'inventory:read', input.now);
  input.proofSignature = await signChallenge(network.agent, input.challenge);
  input.claims = input.claims.slice(0, 2);
  assert.equal((await verifier.assess(input)).code, 'PROOF_MISSING');
});
test('copied challenge response cannot be replayed for a new nonce', async () => {
  const { input, verifier } = await make();
  input.challenge = verifier.issue('agent:warehouse', 'inventory:read', input.now);
  assert.equal((await verifier.assess(input)).code, 'CHALLENGE_INVALID');
});

test('the same valid proof is refused on replay, including concurrent presentations', async () => {
  const { input, verifier } = await make();
  const outcomes = await Promise.all([verifier.assess(input), verifier.assess(input)]);
  assert.deepEqual(outcomes.map(x => x.code).sort(), ['CHALLENGE_REPLAY', 'TRUST_VERIFIED']);
  assert.equal((await verifier.assess(input)).decision, 'REFUSE');
});