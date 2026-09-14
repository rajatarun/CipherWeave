# Channel binding: the CipherWeave / mcp-observatory contract

mcp-observatory's propose/commit gate decides **whether** a tool call runs.
CipherWeave decides **how** the data flow that call creates must be protected.
This document specifies how the second decision rides inside the first, so that
a call the gate allows also carries the channel strength it must run over, and
an executor cannot silently downgrade the transport for a high-risk flow.

The mechanical changes on the observatory side are specified separately, ready
to apply, in `gate-integration-patch.md`. This file is the contract: what is
promised, and why the promise holds. It follows the form of mcp-observatory's
`docs/gate-properties.md`, whose properties P1–P5 are assumed throughout; the
two properties added here continue that numbering as P6 and P7.

---

## 1. The propose-time call

At proposal time, before any token is issued, the gate asks CipherWeave what the
prospective call requires:

```python
from cipherweave.gate_integration import required_profile

decision = required_profile(
    agent_id,                     # who would make the call
    destination_url,              # where the data would go
    classification="CONFIDENTIAL",  # PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED | TOP_SECRET
    regulations=["GDPR"],         # [] means "none apply"; omitting it is a different claim
)

decision.profile          # CipherProfile
decision.token_value      # "CHEAP" | "BALANCED" | "HARDENED" | "QUANTUM_SAFE"
decision.justification    # why, in one line, for the audit record
decision.fail_secure      # True if this is the catch-all answer, not the graph's
decision.as_audit_dict()  # flat JSON-safe view for the proposal row
```

`required_profile_async` is the same function for a caller that already has an
event loop, which the observatory proposer does; prefer it there.

The call does not derive keys and does not write to CipherWeave's drift history.
A proposal may never be committed, so it is not an observation about the agent's
behaviour and must not move the agent's baseline. Key material is issued by the
MCP tool at execution time, from the same decision path.

---

## 2. The token field

| Field | Type | Allowed values | Where |
|---|---|---|---|
| `required_cipher_profile` | JSON string | `"CHEAP"`, `"BALANCED"`, `"HARDENED"`, `"QUANTUM_SAFE"` | inside the commit token's signed payload `P` |

Exactly one field is added, and it carries only the profile. The justification,
evidence trail, risk score and drift alert do **not** go in the token: they are
unbounded in size, P5 bounds the gate's cost by bounding its inputs, and nothing
at commit time needs to read them. They go in the proposal row instead
(`as_audit_dict()` names the keys), which is where an auditor reconstructing a
decision looks anyway.

The value is always present. There is no "absent means unconstrained" spelling,
for the reason given in §5.

---

## P6 — The profile is bound by the signature

**Proposition.** A commit token whose `required_cipher_profile` differs in any
way from the value the issuer placed there — changed to a weaker profile,
changed to a stronger one, removed, or added to a token issued without it — is
rejected with `bad_signature`.

*Proof.* By P3. The MAC is computed over the exact serialised payload bytes and
`verify` recomputes it over the received bytes; `required_cipher_profile` is a
field of that payload, so any edit to it changes the MAC input and acceptance
would be a MAC forgery. Removing the field changes the bytes for the same
reason, as does adding it to a payload that did not contain it, because
canonical serialisation (`sort_keys`, compact separators) makes the byte string
a function of the field set. ∎

**Why this is the whole point.** A downgrade attack on this integration is an
attempt to present a weaker `required_cipher_profile` at commit than the one
scored at propose. P6 says that attempt is not a policy question the verifier
has to adjudicate — it is a forged token, indistinguishable from any other
forgery, caught by the same comparison. The attacker's only remaining move is to
obtain a *legitimate* token for a weaker profile, which requires convincing
CipherWeave at propose time that the flow is lower risk; that is an attack on
the risk graph, not on the gate, and the graph's own controls (authorization
edges, the compliance floor, the drift statistic's input disjointness) are what
stand there.

The existing P3 test enumerates every field of the payload by reading them from
an issued token, so `required_cipher_profile` is covered by it automatically as
soon as the issuer emits it. That is a property of how the test was written, and
it is worth not breaking.

---

## 3. What the commit side must check

At commit, after the argument-hash guard and **before** the nonce is consumed,
the verifier compares the channel the executor will actually use against the
profile under the signature:

```
strength(actual_channel) >= strength(token.required_cipher_profile)
```

on the total order `CHEAP < BALANCED < HARDENED < QUANTUM_SAFE`
(`CipherProfile.strength()`; `ProfileDecision.satisfied_by()` implements exactly
this comparison, so both sides can share one reading of it).

- **Meets or exceeds → proceed** to the nonce guard and then the side effect.
- **Below, unparseable, or unstated → reject** with reason
  **`channel_below_required_profile`**.

That reason is distinct from every existing one. It is not `args_hash_mismatch`
— the arguments are intact and the call is the call that was scored; what
differs is the channel it would run over. It is not `bad_signature` — the token
is authentic. Collapsing it into either would make the one failure this
integration exists to detect indistinguishable in the audit log from an ordinary
argument edit, which defeats the purpose of recording reasons at all.

The ordering matters. `nonce_seen` records the nonce as spent on first sight, so
any guard placed after it burns the nonce on rejection: a caller whose executor
reported the wrong channel could not retry with the right one, and a one-line
misconfiguration would consume every token it touched. The channel guard
therefore sits between the argument hash and the nonce.

**What this check does and does not establish.** The channel value is reported
by the executor. The check binds that *claim* to the signed requirement; it does
not measure the wire. An executor that reports `QUANTUM_SAFE` and opens a plain
TLS 1.2 socket defeats it, exactly as an executor that ignores the gate's ALLOW
entirely defeats the gate. What the integration buys is that the requirement is
now (a) decided by policy rather than by the executor, (b) immutable between
propose and commit, and (c) recorded — so a downgrade is either a refusal or a
lie that is attributable after the fact, rather than a silent default. Trusted
execution of the transport itself is outside this model, as key compromise is
outside P3/P4.

---

## 4. Ordering with the existing guards

The commit path becomes, in order:

1. proposal exists and its recorded decision is `allow` (P4.1)
2. token authentic and unexpired (P4.2, P3)
3. `token.proposal_id == proposal_id` (P4.3)
4. `token.tool_name == τ'` (P4.4)
5. `token.tool_args_hash == H(a')` (P4.5)
6. **`strength(channel) >= strength(token.required_cipher_profile)`** — new
7. nonce not seen before (P4.6)

P4's proposition extends by one clause with no change to its proof: the
verification is still a sequence of guards each of which returns a non-`ok`
result on failure, `ok` is returned only after all of them pass, and the new
guard is one more such. The corollary is correspondingly extended: the only call
that can execute is the call that was scored and allowed, over a channel at
least as strong as the one scored for it, once.

---

## 5. When CipherWeave is unreachable at propose time

The field is still emitted, with the value `"QUANTUM_SAFE"`.

`required_profile` never raises and never returns "no requirement". Graph
unreachable, agent unknown or unauthorized, metadata that cannot be classified,
a timeout, a defect anywhere under the decision path — each yields
`profile = QUANTUM_SAFE`, `fail_secure = True`, and `error` naming the cause,
which the proposer writes into the proposal row. This is ADR-001 applied at the
integration boundary: the cost of a false positive is a stronger channel than
necessary; the cost of a false negative is regulated data on a weak one.

Two spellings were rejected and should stay rejected:

- **Omit the field when the lookup fails.** Then an outage is a downgrade, and
  the cheapest way for an attacker to get a weak channel is to make CipherWeave
  unreachable — a policy engine whose failure mode is "no policy" is worse than
  no policy engine, because the system is built as though there is one.
- **Fail the proposal.** Defensible, and a deployment may layer it on top by
  testing `fail_secure`. It is not the default because a proposer that hard-fails
  on an unreachable dependency is a proposer someone will "temporarily" wire to
  skip the dependency, and that edit is permanent.

For symmetry, the verifier treats an **absent** `required_cipher_profile` as
`QUANTUM_SAFE` rather than as unconstrained. During rollout this makes tokens
issued by an old proposer safe-by-default rather than silently exempt; after
rollout it is unreachable, because stripping the field breaks the signature
(P6). An absent field is never a bypass on either interpretation; treating it as
the strongest requirement simply means the same answer is reached without
relying on P6 to reach it.

---

## P7 — The profile is monotone between propose and commit

**Proposition.** Let `p` be the profile in the signed payload at propose time
and `p'` the profile enforced at commit. Then `strength(p') >= strength(p)`.
The requirement may be raised between the two phases; it can never be lowered.

*Proof.* There are exactly two ways `p'` can differ from `p`.

1. **The payload value changes.** Rejected by P6 — not a lowering, a forgery.
2. **The verifier re-evaluates and joins.** If a deployment re-queries
   CipherWeave at commit (because the graph may have learned something in the
   intervening seconds — a new threat indicator, a drift alert), the enforced
   requirement is
   `p' = combine(p, p_fresh)`, where `combine` is defined in
   `src/cipherweave/scoring.py` as the join over the profile lattice: it returns
   the strongest of its arguments. A join satisfies `p' >= p` for every `p_fresh`
   by definition of least upper bound, so re-evaluation can only raise. ∎

**Why it composes with the lattice join already in `scoring.py`.** The
monotonicity is not an extra rule bolted onto the integration; it is the same
property CipherWeave already has internally, extended across the propose/commit
boundary. Inside one decision, every mechanism that can affect the outcome —
`Π(r)` from the decayed evidence aggregate, the mandatory-regime compliance
floor, and the drift override — is *raise-only*, and all of them enter through
`combine`, which is exactly why `scoring.py` documents the result as "never
weaker than any individual mechanism demanded" (Proposition 3). Adding a phase
boundary adds one more argument to the same join. The chain
`CHEAP < BALANCED < HARDENED < QUANTUM_SAFE` is totally ordered, so the join is
just `max` over `strength()`, it is associative and commutative, and it does not
matter whether propose-time evidence and commit-time evidence are combined in
one call or two. A downgrade between phases would require either forging the
HMAC or a join returning something weaker than one of its arguments; neither is
available.

**Practical consequence.** Raising is safe and needs no protocol change: a
verifier that re-queries and joins can only reject calls it would otherwise have
allowed. Lowering requires re-running the proposal, which means re-scoring the
call under the gate's own policy — which is correct, because a weaker channel is
a different authorization, not a relaxation of the same one.

---

## 6. What is *not* claimed

- Nothing here says `QUANTUM_SAFE` is the right requirement for any particular
  flow. That is the risk graph's judgement, it depends on the topology an
  operator seeded, and CipherWeave's own documentation is explicit that JIT-
  registered paths are inferred rather than asserted (ADR-016).
- The channel comparison verifies a reported value, not the wire (§3).
- Fail-secure means the *profile* is safe under failure. It does not mean the
  call is safe: a `fail_secure = True` decision says CipherWeave could not
  evaluate the flow at all, and a deployment that cares should treat that as an
  operational alert rather than as a successful policy evaluation that happened
  to return the strongest answer.
- P6 and P7 assume the commit secret is uncompromised and the proposal store is
  not writable by the caller, inheriting the assumptions of P3 and P4.
