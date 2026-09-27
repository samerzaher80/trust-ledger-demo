import test from 'node:test';
import assert from 'node:assert/strict';
import { assessTask, createChallenge, createSyntheticNetwork, signChallenge } from '../trust.js';

const make = async () => {
  const network = await createSyntheticNetwork();
  const input = {
    agentId: 'agent:courier-7', agentPublicKey: network.agent.publicKey,
    requestScope: 'inventory:read', audience: 'agent:warehouse', claims: network.claims,
    anchors: { organization: network.organization.publicKey, peer: network.peer.publicKey },
    now: network.now, revokedIds: [],
    challenge: createChallenge('agent:warehouse', 'inventory:read', network.now)
  };
  input.proofSignature = await signChallenge(network.agent, input.challenge);
  return { network, input };
};

test('signed scope and independent reputation evidence allow the task', async () => {
  const { input } = await make();
  assert.equal((await assessTask(input)).decision, 'ACCEPT');
});
test('copied credentials fail when the presenting key changes', async () => {
  const { network, input } = await make();
  input.agentPublicKey = network.impostor.publicKey;
  input.proofSignature = await signChallenge(network.impostor, input.challenge);
  assert.equal((await assessTask(input)).code, 'IDENTITY_MISMATCH');
});
test('revoked authority fails even with a valid signature', async () => {
  const { input } = await make();
  input.revokedIds = ['cap-104'];
  assert.equal((await assessTask(input)).code, 'REVOKED');
});
test('task scope and audience cannot be widened', async () => {
  const { network, input } = await make();
  input.requestScope = 'payment:send';
  input.challenge = createChallenge('agent:warehouse', input.requestScope, input.now);
  input.proofSignature = await signChallenge(network.agent, input.challenge);
  assert.equal((await assessTask(input)).code, 'OUT_OF_SCOPE');
  input.requestScope = 'inventory:read'; input.audience = 'agent:bank';
  input.challenge = createChallenge(input.audience, input.requestScope, input.now);
  input.proofSignature = await signChallenge(network.agent, input.challenge);
  assert.equal((await assessTask(input)).code, 'WRONG_AUDIENCE');
});
test('tampering with a signed claim fails verification', async () => {
  const { input } = await make();
  input.claims = structuredClone(input.claims);
  input.claims[0].payload.scopes.push('payment:send');
  assert.equal((await assessTask(input)).code, 'SIGNATURE_INVALID');
});
test('expiry and missing independent vouch fail closed', async () => {
  const { network, input } = await make();
  input.now += 172_800_000;
  input.challenge = { ...input.challenge, issuedAt: input.now };
  input.proofSignature = await signChallenge(network.agent, input.challenge);
  assert.equal((await assessTask(input)).code, 'EXPIRED');
  input.now -= 172_800_000; input.challenge = createChallenge('agent:warehouse', 'inventory:read', input.now);
  input.proofSignature = await signChallenge(network.agent, input.challenge);
  input.claims = input.claims.slice(0, 2);
  assert.equal((await assessTask(input)).code, 'PROOF_MISSING');
});
test('copied challenge response cannot be replayed for a new nonce', async () => {
  const { input } = await make();
  input.challenge = createChallenge('agent:warehouse', 'inventory:read', input.now);
  assert.equal((await assessTask(input)).code, 'CHALLENGE_INVALID');
});
