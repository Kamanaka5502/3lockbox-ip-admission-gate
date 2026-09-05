(() => {
  const root = document;
  const body = document.body;
  const qs = s => root.querySelector(s);
  const qsa = s => [...root.querySelectorAll(s)];
  const wait = ms => new Promise(r => setTimeout(r, ms));

  const boundaryData = {
    candidate: {
      name: 'Candidate Surface',
      purpose: 'Establish input admissibility before any provider lookup or downstream effect.',
      evidence: 'A syntactically valid, globally routable IPv4 or IPv6 address.',
      consequence: 'Allows evidence acquisition to proceed.',
      closure: 'Private, loopback, reserved, link-local, multicast, and invalid inputs stop before provider access.',
      blind: 'Blind spot addressed: many pipelines begin processing before input admissibility is established.',
      stage: 'candidate',
      math: 'x ∈ PublicIP ⇒ acquire(x)'
    },
    evidence: {
      name: 'Evidence Acquisition Boundary',
      purpose: 'Normalize IP2Location.io network intelligence into a governed evidence envelope.',
      evidence: 'Country, ASN, usage classification, and security/risk fields when the configured provider plan exposes them.',
      consequence: 'Creates the evidence snapshot consumed by policy.',
      closure: 'Missing or insufficient evidence cannot silently become a clean admit; uncertainty remains constrained.',
      blind: 'Blind spot addressed: lookup output is evidence, not authority and not final truth.',
      stage: 'evidence',
      math: 'E = normalize(IP2Location(x))'
    },
    policy: {
      name: 'Policy Admission Boundary',
      purpose: 'Evaluate whether normalized evidence survives the active versioned rule set.',
      evidence: 'Evidence envelope + active policy version + explicit allow/deny/risk thresholds.',
      consequence: 'Computes ADMIT, REVIEW, or REFUSE.',
      closure: 'Hard deny matches and configured risk ceilings block motion before effect binds.',
      blind: 'Blind spot addressed: rules are not governance unless their result is bound to execution.',
      stage: 'policy',
      math: 'decision = P_v(E)'
    },
    consequence: {
      name: 'Consequence Lock Boundary',
      purpose: 'Bind the only outcome allowed to affect the protected execution path.',
      evidence: 'Completed evaluated state under a known policy version.',
      consequence: 'HTTP enforcement and machine-readable ADMIT / REVIEW / REFUSE state.',
      closure: 'Unresolved review or refusal never becomes implicit success.',
      blind: 'Blind spot addressed: analytics can describe risk without ever controlling consequence.',
      stage: 'consequence',
      math: 'bind(c) iff c ∈ {A,R,F}'
    },
    proof: {
      name: 'Proof Emission Boundary',
      purpose: 'Seal decision truth into a deterministic replayable receipt.',
      evidence: 'Canonical request + evidence snapshot + fired rules + policy version + decision.',
      consequence: 'Emits a deterministic SHA-256 decision proof.',
      closure: 'A replay mismatch exposes integrity or policy-state divergence.',
      blind: 'Blind spot addressed: a historical decision should be reproducible, not merely logged.',
      stage: 'proof',
      math: 'H_d = SHA256(request∥E∥rules∥P_v∥c)'
    },
    ledger: {
      name: 'Ledger Continuity Boundary',
      purpose: 'Preserve local decision ordering independently from deterministic receipt replay.',
      evidence: 'Previous ledger hash + sequence + decision proof + decision + policy version.',
      consequence: 'Appends a tamper-evident event-order proof.',
      closure: 'Mutation, deletion, or reordering becomes detectable by chain verification.',
      blind: 'Blind spot addressed: logs record events; custody chains make sequence integrity testable.',
      stage: 'proof',
      math: 'H_n = SHA256(n∥H_d∥c∥P_v∥H_{n-1})'
    },
    authority: {
      name: 'Authority Custody Boundary',
      purpose: 'Separate observation from the authority that is allowed to bind consequence.',
      evidence: 'Versioned policy evaluation and an intact execution path.',
      consequence: 'Only validated policy output may authorize effect.',
      closure: 'No valid custody path means no consequence is admitted.',
      blind: 'Blind spot addressed: visibility, scoring, and dashboards are not equivalent to execution authority.',
      stage: 'policy',
      math: 'authority ≠ evidence; authority = valid(P_v,E)'
    },
    replay: {
      name: 'Replay Integrity Boundary',
      purpose: 'Recompute past truth from the stored evidence snapshot rather than a fresh external lookup.',
      evidence: 'Original receipt snapshot + original policy version.',
      consequence: 'Confirms whether the same decision proof reproduces.',
      closure: 'Historical truth cannot drift silently with later provider or network changes.',
      blind: 'Blind spot addressed: re-querying the present is not the same as replaying the past.',
      stage: 'proof',
      math: 'replay(snapshot,P_v) = H_d'
    },
    threshold: {
      name: 'Admissibility Threshold',
      purpose: 'Convert configured country, ASN, hosting, proxy, VPN, Tor, and fraud conditions into explicit gates.',
      evidence: 'Observed provider fields and operator-selected policy thresholds.',
      consequence: 'Escalates or refuses before protected effect occurs.',
      closure: 'Threshold breach is explicit and machine enforceable.',
      blind: 'Blind spot addressed: risk indicators only matter when tied to a defined boundary and outcome.',
      stage: 'policy',
      math: 'risk(E) ≤ τ ⇒ eligible'
    }
  };

  const card = qs('#boundaryCard');
  const cardName = qs('#bcName');
  const cardPurpose = qs('#bcPurpose');
  const cardEvidence = qs('#bcEvidence');
  const cardConsequence = qs('#bcConsequence');
  const cardClosure = qs('#bcClosure');
  const cardBlind = qs('#bcBlind');
  const cardMath = qs('#bcMath');
  const closeCard = qs('#bcClose');
  const mathTokens = qsa('.math-token');
  const interactionNodes = qsa('[data-boundary]');
  let hideTimer = null;

  function stageGlow(stage) {
    qsa('.stage-node').forEach(n => n.classList.toggle('hover-hot', n.dataset.stage === stage));
    mathTokens.forEach(t => t.classList.toggle('active', t.dataset.stage === stage || t.dataset.boundary === stage));
  }

  function showBoundary(key, el) {
    const d = boundaryData[key];
    if (!d || !card) return;
    clearTimeout(hideTimer);
    cardName.textContent = d.name;
    cardPurpose.textContent = d.purpose;
    cardEvidence.textContent = d.evidence;
    cardConsequence.textContent = d.consequence;
    cardClosure.textContent = d.closure;
    cardBlind.textContent = d.blind;
    cardMath.textContent = d.math;
    card.classList.add('visible');
    interactionNodes.forEach(n => n.classList.toggle('active', n === el || n.dataset.boundary === key));
    stageGlow(d.stage);
  }

  function hideBoundary(delay = 120) {
    clearTimeout(hideTimer);
    hideTimer = setTimeout(() => {
      card?.classList.remove('visible');
      interactionNodes.forEach(n => n.classList.remove('active'));
      qsa('.stage-node').forEach(n => n.classList.remove('hover-hot'));
      mathTokens.forEach(t => t.classList.remove('active'));
    }, delay);
  }

  interactionNodes.forEach(el => {
    const key = el.dataset.boundary;
    el.addEventListener('pointerenter', () => showBoundary(key, el));
    el.addEventListener('focus', () => showBoundary(key, el));
    el.addEventListener('click', () => showBoundary(key, el));
    el.addEventListener('pointerleave', () => hideBoundary(220));
    el.addEventListener('blur', () => hideBoundary(220));
  });
  card?.addEventListener('pointerenter', () => clearTimeout(hideTimer));
  card?.addEventListener('pointerleave', () => hideBoundary(120));
  closeCard?.addEventListener('click', () => hideBoundary(0));

  // Stronger pointer depth: world moves least, rings more, core most.
  const coreWrap = qs('#coreWrap');
  const world = qs('#worldField');
  const mathField = qs('#mathField');
  const orb = qs('#orb');
  if (coreWrap) {
    coreWrap.addEventListener('pointermove', e => {
      if (body.classList.contains('motion-paused')) return;
      const r = coreWrap.getBoundingClientRect();
      const nx = (e.clientX - r.left) / r.width - .5;
      const ny = (e.clientY - r.top) / r.height - .5;
      body.style.setProperty('--parallax-x', `${nx * 18}px`);
      body.style.setProperty('--parallax-y', `${ny * 14}px`);
      if (world) world.style.transform = `translate3d(${nx * -12}px,${ny * -8}px,-170px) rotateX(${6 + ny * -3}deg) rotateY(${nx * 3}deg)`;
      if (mathField) mathField.style.transform = `translate3d(${nx * 8}px,${ny * 6}px,20px) rotateY(${nx * 4}deg) rotateX(${ny * -3}deg)`;
      if (orb) orb.style.translate = `${nx * 8}px ${ny * 6}px 0`;
    });
    coreWrap.addEventListener('pointerleave', () => {
      if (world) world.style.transform = 'translateZ(-170px) rotateX(6deg)';
      if (mathField) mathField.style.transform = '';
      if (orb) orb.style.translate = '';
    });
  }

  // Numeric symbolic field. These values are visualization telemetry, not backend metrics.
  const dyn = qsa('[data-dynamic-math]');
  let raf = 0;
  function animateMath(t) {
    const s = t / 1000;
    const vals = [
      0.5 + 0.5 * Math.sin(s * .71),
      0.5 + 0.5 * Math.sin(s * .43 + 1.8),
      0.5 + 0.5 * Math.cos(s * .57 + .7),
      0.5 + 0.5 * Math.sin(s * .31 + 2.4)
    ];
    dyn.forEach((el, i) => {
      const v = vals[i % vals.length];
      el.textContent = `${el.dataset.dynamicMath} ${v.toFixed(4)}`;
    });
    raf = requestAnimationFrame(animateMath);
  }
  raf = requestAnimationFrame(animateMath);

  // Mirror the real receipt hash into the orbit when one exists.
  const receipt = qs('#decisionHash');
  const hashEcho = qs('#hashEcho');
  if (receipt && hashEcho) {
    const syncHash = () => {
      const h = receipt.textContent.trim();
      hashEcho.textContent = /^[0-9a-f]{32,}$/i.test(h) ? `H_d ${h.slice(0,8)}…${h.slice(-6)}` : 'H_d awaiting proof';
    };
    new MutationObserver(syncHash).observe(receipt, {childList:true,characterData:true,subtree:true});
    syncHash();
  }

  // Bind visual intensity to real runtime state changes.
  let intensityTimer = null;
  function reactToState() {
    const state = body.dataset.state || 'WAITING';
    clearTimeout(intensityTimer);
    if (state === 'PENDING') {
      body.classList.add('field-intensity');
      qsa('.map-node').forEach((n,i) => setTimeout(() => n.classList.add('active'), i * 70));
    } else {
      body.classList.add('field-intensity');
      intensityTimer = setTimeout(() => body.classList.remove('field-intensity'), 2200);
      setTimeout(() => qsa('.map-node').forEach(n => n.classList.remove('active')), 1400);
    }
  }
  new MutationObserver(reactToState).observe(body, {attributes:true,attributeFilter:['data-state']});

  // Stage mutation observer: lights the matching mathematical boundary while the real pipeline runs.
  const pipeline = qs('.pipeline');
  if (pipeline) {
    new MutationObserver(() => {
      const hot = qs('.stage-node.hot');
      if (!hot) return;
      mathTokens.forEach(t => t.classList.toggle('active', t.dataset.stage === hot.dataset.stage));
    }).observe(pipeline, {attributes:true,subtree:true,attributeFilter:['class']});
  }

  // Clean up if browser page lifecycle freezes the tab.
  addEventListener('pagehide', () => cancelAnimationFrame(raf), {once:true});
})();
