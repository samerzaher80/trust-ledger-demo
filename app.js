import { assessTask, createChallenge, createSyntheticNetwork, signChallenge } from './trust.js';

const $ = id => document.getElementById(id);
const scenarios = {
  baseline: { title: 'Warehouse asks Courier-7 for inventory', description: 'A warehouse agent accepts a lookup only when identity, signed authority, task scope, and independent evidence agree.', scope: 'inventory:read', caseId: 'TL-001' },
  spoof: { title: 'An impostor copies Courier-7’s claims', description: 'The same credential bundle is presented from a different public key. The subject binding must stop impersonation.', scope: 'inventory:read', caseId: 'TL-002' },
  revoked: { title: 'The organization revokes access', description: 'The signature is still valid, but the grant ID appears in the verifier’s local revocation list.', scope: 'inventory:read', caseId: 'TL-003' },
  scope: { title: 'Courier-7 asks to send a payment', description: 'The signed grant permits inventory reading. A stronger action cannot be inferred from good reputation.', scope: 'payment:send', caseId: 'TL-004' },
  tamper: { title: 'A proof is edited after signing', description: 'An attacker adds payment authority to the capability payload without obtaining a fresh issuer signature.', scope: 'payment:send', caseId: 'TL-005' }
};
const claimLabels = { capability: ['SIGNED CAPABILITY', 'Northstar Operations', 'inventory:read · warehouse audience'], 'action-receipt': ['SIGNED ACTION RECEIPT', 'Northstar Operations', 'prior fulfilled inventory lookup'], vouch: ['INDEPENDENT VOUCH', 'Harbor Partner', 'joint handoff attested'] };
let network;
let selected = 'baseline';

function renderProfile() {
  const caseData = scenarios[selected];
  $('scenario-title').textContent = caseData.title;
  $('scenario-description').textContent = caseData.description;
  $('request-scope').textContent = caseData.scope;
  $('case-id').textContent = `CASE / ${caseData.caseId}`;
  $('agent-name').textContent = selected === 'spoof' ? 'unknown agent (claiming Courier-7)' : 'agent:courier-7';
  $('fingerprint').textContent = (selected === 'spoof' ? network.impostor.keyId : network.agent.keyId).slice(0, 27) + '…';
  $('proof-list').replaceChildren(...network.claims.map((claim, index) => {
    const [label, issuer, detail] = claimLabels[claim.payload.type];
    const row = document.createElement('div'); row.className = 'proof-row';
    const left = document.createElement('div');
    const tag = document.createElement('span'); tag.textContent = `0${index + 1} / ${label}`;
    const name = document.createElement('strong'); name.textContent = issuer;
    const small = document.createElement('small'); small.textContent = detail;
    left.append(tag, name, small);
    const right = document.createElement('code'); right.textContent = `${claim.payload.id} · ${claim.signature.slice(0, 11)}…`;
    row.append(left, right); return row;
  }));
  document.querySelectorAll('.scenario').forEach(button => button.classList.toggle('active', button.dataset.scenario === selected));
}

async function run() {
  if (!network) return;
  const button = $('evaluate'); button.disabled = true; button.textContent = 'Verifying…';
  const caseData = scenarios[selected];
  const claims = structuredClone(network.claims);
  if (selected === 'tamper') claims[0].payload.scopes.push('payment:send');
  const presenter = selected === 'spoof' ? network.impostor : network.agent;
  const now = Date.now();
  const challenge = createChallenge('agent:warehouse', caseData.scope, now);
  const proofSignature = await signChallenge(presenter, challenge);
  const result = await assessTask({
    agentId: 'agent:courier-7', agentPublicKey: presenter.publicKey,
    requestScope: caseData.scope, audience: 'agent:warehouse', claims,
    anchors: { organization: network.organization.publicKey, peer: network.peer.publicKey },
    revokedIds: selected === 'revoked' ? ['cap-104'] : [], now, challenge, proofSignature
  });
  $('decision-band').classList.toggle('accepted', result.decision === 'ACCEPT');
  $('decision-band').classList.toggle('refused', result.decision === 'REFUSE');
  $('decision').textContent = result.decision;
  $('decision-detail').textContent = result.detail;
  $('decision-code').textContent = result.code;
  $('trace-list').replaceChildren(...[...result.checks.map(text => ({ text, pass: true })), { text: result.code, pass: result.decision === 'ACCEPT' }].map((item, index) => {
    const li = document.createElement('li'); li.className = item.pass ? 'pass' : 'fail';
    const number = document.createElement('span'); number.textContent = String(index + 1).padStart(2, '0');
    const label = document.createElement('strong'); label.textContent = item.text;
    li.append(number, label); return li;
  }));
  button.innerHTML = 'Verify again <span>↗</span>'; button.disabled = false;
}

document.querySelectorAll('.scenario').forEach(button => button.addEventListener('click', async () => {
  selected = button.dataset.scenario;
  renderProfile();
  await run();
}));
$('evaluate').addEventListener('click', run);

try {
  network = await createSyntheticNetwork();
  renderProfile();
  await run();
} catch (error) {
  $('decision').textContent = 'UNAVAILABLE';
  $('decision-detail').textContent = 'This browser must support Web Crypto P-256 and secure HTTPS.';
  $('decision-code').textContent = 'CRYPTO_ERROR';
  console.error(error);
}
