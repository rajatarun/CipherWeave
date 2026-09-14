# Patch specification: channel binding in mcp-observatory

Ready-to-apply changes for the **mcp-observatory** side of the contract in
`gate-integration.md`. Nothing here has been applied — this repository does not
edit mcp-observatory. Every path, function name, field name and code excerpt
below was read from `mcp-observatory` at `origin/main` (the Python edition;
see "Branch caveat" at the end).

Summary of the change: the commit token gains one signed field,
`required_cipher_profile`; the commit verifier gains one guard and one rejection
reason, `channel_below_required_profile`; the proposer obtains the value from
CipherWeave at propose time and fails secure to `QUANTUM_SAFE`.

---

## 0. Dependency

The proposer imports from CipherWeave:

```python
from cipherweave.gate_integration import required_profile_async
```

`ToolProposer.propose` is already `async`, so the async form is the right one —
the synchronous `required_profile` would block the proposer's loop.

CipherWeave must be importable in the proposer's environment and its policy
components initialized once at start-up, either by running the MCP server in the
same process or by calling `cipherweave.gate_integration.configure(risk_graph,
drift_detector)`. If neither has happened, every lookup fails secure to
`QUANTUM_SAFE` and says so in `decision.error` — correct, but it means a
misconfigured deployment binds every call to the strongest channel rather than
failing loudly, so the start-up path should assert the components are present.

---

## 1. `mcp_observatory/proposal_commit/token.py`

### 1.1 `CommitTokenManager.issue`

Add a keyword-only parameter and one payload field.

```python
    def issue(
        self,
        *,
        proposal_id: str,
        tool_name: str,
        tool_args_hash: str,
        composite_score: float,
        required_cipher_profile: str,          # NEW — no default, see note
    ) -> TokenIssueResult:
        issued_at = int(time())
        token_payload = {
            "token_id": str(uuid4()),
            "proposal_id": proposal_id,
            "tool_name": tool_name,
            "tool_args_hash": tool_args_hash,
            "issued_at": issued_at,
            "expires_at": issued_at + self.ttl_seconds,
            "nonce": str(uuid4()),
            "composite_score": composite_score,
            "required_cipher_profile": required_cipher_profile,   # NEW
        }
```

Nothing else in this file changes. `verify` treats the payload as opaque and
already covers the new field: it recomputes the MAC over the received bytes, so
P6 follows from P3 with no code change. Serialisation is already canonical
(`json.dumps(..., sort_keys=True, separators=(",", ":"))`), so the added key
takes its place deterministically.

**No default value.** A default would let a caller that has not been updated
mint tokens silently, and whatever the default were, it would be either a
downgrade (`"CHEAP"`) or a lie about having consulted CipherWeave
(`"QUANTUM_SAFE"`). Making it required means the compiler-equivalent — a
`TypeError` at the one call site in §2 — is the migration checklist.

**Value validation.** Reject anything outside
`{"CHEAP", "BALANCED", "HARDENED", "QUANTUM_SAFE"}` at issue time with
`ValueError`. An unparseable value is already refused at commit (§3), but
refusing it at issue keeps an unenforceable token from ever existing.

### 1.2 Execution tokens

`mcp_observatory/token/verifier.py` handles the separate v2 *execution* token
path, which `tests/test_gate_properties.py::test_p3_execution_token_every_field_is_bound_by_the_signature`
also covers. It is **out of scope** for this patch and unchanged. If channel
binding is later wanted there too, it is the same one-field change; do it as its
own patch so the two token formats do not migrate in one step.

---

## 2. `mcp_observatory/proposal_commit/proposer.py`

### 2.1 `ToolProposer.propose` signature

Add the flow identifiers CipherWeave needs. They are optional so that tools with
no outbound data flow keep working; when they are absent the proposer must still
emit a profile, and it emits the fail-secure one.

```python
    async def propose(
        self,
        *,
        tool_name: str,
        tool_args: dict[str, Any],
        prompt: str,
        candidate_output_a: Optional[str] = None,
        candidate_output_b: Optional[str] = None,
        agent_id: Optional[str] = None,              # NEW
        destination_url: Optional[str] = None,       # NEW
        data_classification: Optional[str] = None,   # NEW
        regulations: Optional[Sequence[str]] = None, # NEW
    ) -> dict[str, Any]:
```

### 2.2 The lookup

Place it immediately before the existing `token = self.token_manager.issue(...)`
call (proposer.py:120 at `origin/main`), inside the `decision == "allow"` path.
A blocked proposal issues no token, so it needs no profile — and skipping the
lookup there also keeps the input-size refusal (`input_too_large`) free of an
outbound dependency, which matters because that branch exists precisely to
refuse work before doing any.

```python
        if agent_id and destination_url:
            cipher = await required_profile_async(
                agent_id,
                destination_url,
                classification=data_classification,
                regulations=list(regulations) if regulations is not None else None,
            )
        else:
            cipher = _no_flow_profile()   # see below

        token = self.token_manager.issue(
            proposal_id=proposal_id,
            tool_name=tool_name,
            tool_args_hash=args_digest,
            composite_score=score,
            required_cipher_profile=cipher.token_value,
        )
```

`_no_flow_profile()` returns a `ProfileDecision` with
`profile=CipherProfile.QUANTUM_SAFE`, `fail_secure=True` and an `error` of
`"no flow identifiers supplied"`. Construct it once as a module constant. The
temptation is to emit `CHEAP` for a tool with no outbound flow; resist it. "No
identifiers were supplied" and "this call sends nothing anywhere" are not the
same statement, and only the caller can tell them apart — a caller that can
should pass identifiers.

`required_profile_async` never raises, so no `try` is needed and none should be
added: a bare `except` here would be able to swallow the fail-secure answer.

### 2.3 The allowed response

Add the profile and the explanation to the dict returned on `status == "allowed"`:

```python
        return {
            "status": "allowed",
            ...
            "commit_token": token.token,
            "token_id": token.token_id,
            "required_cipher_profile": cipher.token_value,   # NEW
            "cipher_decision": cipher.as_audit_dict(),       # NEW
        }
```

The caller needs `required_cipher_profile` to know which channel to open, and
`cipher_decision` carries the justification, evidence trail, risk score, drift
flag and `fail_secure` marker into the audit record — the token deliberately
carries none of that (`gate-integration.md` §2).

### 2.4 Persisting it

`self.storage.save_proposal(...)` gains `required_cipher_profile=cipher.token_value`.
See §5.

---

## 3. `mcp_observatory/proposal_commit/verifier.py`

### 3.1 The rejection reason

```python
#: The executor's channel is weaker than the profile bound into the token.
#: Distinct from args_hash_mismatch (the call is the call that was scored) and
#: from bad_signature (the token is authentic) -- what differs is the channel.
CHANNEL_BELOW_REQUIRED_PROFILE = "channel_below_required_profile"
```

### 3.2 `CommitVerifier.verify_commit`

Add one parameter and one guard. The guard goes **after** the
`tool_args_hash` comparison and **before** `self.storage.nonce_seen(...)`:
`nonce_seen` marks the nonce spent on first sight, so a guard after it would
burn the token on a rejection and make the correct retry impossible.

```python
    async def verify_commit(
        self,
        *,
        proposal_id: str,
        commit_token: str,
        tool_name: str,
        tool_args: dict,
        channel_profile: str | None = None,      # NEW
    ) -> CommitVerification:
        ...
        args_digest = tool_args_hash(tool_args)
        if payload.get("tool_args_hash") != args_digest:
            return CommitVerification(ok=False, reason="args_hash_mismatch")

        # NEW -- channel binding. An absent field is read as QUANTUM_SAFE, not as
        # unconstrained, so a token minted before this field existed fails secure
        # during rollout rather than being silently exempt.
        required = str(payload.get("required_cipher_profile") or "QUANTUM_SAFE")
        if not _channel_satisfies(channel_profile, required):
            return CommitVerification(ok=False, reason=CHANNEL_BELOW_REQUIRED_PROFILE)

        expires_at = datetime.fromtimestamp(int(payload["expires_at"]), tz=timezone.utc)
        nonce_replay = await self.storage.nonce_seen(...)
```

### 3.3 `_channel_satisfies`

```python
_PROFILE_STRENGTH = {"CHEAP": 0, "BALANCED": 1, "HARDENED": 2, "QUANTUM_SAFE": 3}


def _channel_satisfies(channel_profile: str | None, required: str) -> bool:
    """True when the executor's channel meets or exceeds the required profile.

    Unknown, unparseable and absent channels satisfy nothing: the same rule that
    produced the requirement in the first place (CipherWeave ADR-001).
    """
    actual = _PROFILE_STRENGTH.get(str(channel_profile or "").upper())
    if actual is None:
        return False
    return actual >= _PROFILE_STRENGTH.get(required.upper(), 3)
```

A `required` value that is not in the table falls to `3` (`QUANTUM_SAFE`), so a
corrupted-but-authentically-signed profile is enforced at maximum rather than
ignored.

The `strength` table duplicates `CipherProfile.strength()` rather than importing
it, deliberately: the verifier must not fail closed on an import of CipherWeave
in a deployment that does not use it. The four names and their order are a
contract between the two systems; if that ever needs to change, it needs a
version field, not a shared import.

---

## 4. Call sites that must pass the channel

`verify_commit` is called from three places. Each must pass `channel_profile`
describing the channel the executor will actually use; passing nothing keeps the
call safe (it rejects) but useless.

| File | Function |
|---|---|
| `mcp_observatory/demo/server.py` | `transfer_funds_commit` (verifier call at line 47 on `origin/main`) |
| `mcp_observatory/demo/real_world_server.py` | commit handler (verifier call at line 256) |
| `tests/test_aws.py` | `verify_commit` call at line 175 |

`mcp_observatory/aws/gate.py::build_gate` (line ~77) wires the proposer,
verifier and token manager together and needs no change — it passes no
per-call arguments.

---

## 5. Storage and schema

### 5.1 `mcp_observatory/proposal_commit/storage.py`

- `ProposalCommitStorage.save_proposal` (abstract, line 38): add
  `required_cipher_profile: str` to the keyword-only signature.
- `InMemoryStorage.save_proposal` takes `**kwargs` and stores the dict — no
  change needed.
- `PostgresStorage.save_proposal` (line 146): extend the INSERT.

```sql
INSERT INTO proposals (proposal_id, tool_name, args_json, prompt_hash,
                       composite_score, decision, created_at,
                       required_cipher_profile)
VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7, $8)
```

with `kwargs["required_cipher_profile"]` appended to the argument list.

### 5.2 `sql/schema.sql`

```sql
ALTER TABLE proposals
    ADD COLUMN IF NOT EXISTS required_cipher_profile TEXT NOT NULL DEFAULT 'QUANTUM_SAFE';
```

and the same column in the `CREATE TABLE IF NOT EXISTS proposals` body for fresh
databases. The default is the fail-secure value, matching `composite_score`'s
existing treatment in `proposer.py` (a proposal with no computable signal is
stored at `1.0`, "the most conservative decision rather than the least").

Storing the full `cipher_decision` audit dict is optional; if wanted, one
`JSONB` column (`cipher_decision JSONB`) is enough and keeps the justification
queryable.

---

## 6. Tests that must accompany the change

In `tests/test_gate_properties.py`, following the file's existing naming
convention (`test_pN_...`), and in `docs/gate-properties.md` as properties P6
and P7 (the file states that every numbered property has a test of the same
number).

1. **`test_p6_required_cipher_profile_is_bound_by_the_signature`** — the
   existing `test_p3_commit_token_every_field_is_bound_by_the_signature` already
   mutates every field read from an issued token, so it covers the new field the
   moment the issuer emits it. Add the targeted case anyway: take an allowed
   proposal, decode the payload, replace `"QUANTUM_SAFE"` with `"CHEAP"`,
   re-sign with `_reassemble`, and assert `verify` returns `bad_signature` — not
   `channel_below_required_profile`. The point is that a downgrade is caught as a
   forgery, and asserting the *reason* is what pins it.

2. **`test_p6_commit_rejects_a_channel_below_the_required_profile`** — an
   allowed proposal whose token requires `HARDENED`, committed with
   `channel_profile="BALANCED"`, is rejected with
   `channel_below_required_profile`; with `"HARDENED"` and with
   `"QUANTUM_SAFE"` it returns `ok`.

3. **`test_p6_unparseable_or_absent_channel_is_rejected`** — `None`, `""`,
   `"AES-256-GCM"` and `"quantum_safe_ish"` all reject. Fail-secure, not
   best-effort parsing.

4. **`test_p6_a_rejected_channel_does_not_burn_the_nonce`** — commit once with a
   too-weak channel (rejected), then commit the same token with a sufficient
   channel and assert `ok`. This is the test that pins the guard *ordering*; it
   fails if the channel check is placed after `nonce_seen`, which is the mistake
   most likely to be made when applying this patch.

5. **`test_p6_a_token_without_the_field_is_treated_as_quantum_safe`** — mint a
   payload with the field removed, sign it with the manager's own key (the test
   holds the secret, so this is legitimate, not a forgery), and assert that
   committing with `channel_profile="BALANCED"` rejects. Covers the rollout
   window.

6. **`test_p7_commit_may_raise_the_required_profile_but_never_lower_it`** — with
   a token requiring `HARDENED`, a verifier configured to join a fresh
   commit-time requirement of `QUANTUM_SAFE` rejects a `HARDENED` channel; a
   fresh requirement of `CHEAP` still rejects a `BALANCED` channel. Both
   directions, because the second is the one that fails if someone writes
   `p' = p_fresh` instead of `p' = max(p, p_fresh)`.

7. **`test_p6_side_effect_does_not_run_on_a_channel_mismatch`** — the analogue
   of `test_p4_no_side_effect_without_a_passing_verification`: drive
   `demo/server.py`'s propose/commit pair with an insufficient channel and assert
   the ledger is untouched. Guard-in-the-verifier is not the same claim as
   no-side-effect-at-the-caller; P4's existing test earned its keep by finding
   exactly that gap.

8. **`test_p6_proposer_fails_secure_when_cipherweave_is_unreachable`** —
   monkeypatch `required_profile_async` to raise, and assert the issued token
   still carries `"QUANTUM_SAFE"` rather than omitting the field or propagating.
   (The CipherWeave client cannot raise; the test asserts the proposer does not
   *depend* on that, which is the property that survives a future refactor.)

CipherWeave's side is already tested in `tests/test_gate_integration.py` there —
fail-secure on graph down, unknown agent, unclassifiable metadata, scoring
defect and timeout; the correct profile on seeded known-risk paths; and that the
gate client and the MCP tool agree on the same flow.

---

## 7. Branch caveat

These paths are read from `origin/main`, the Python edition. The branch checked
out in the working copy at the time of writing (`main-nodejs`) is a TypeScript
port in which the same four modules exist as `src/proposal/{token,proposer,
verifier,storage}.ts`. The design is unchanged by the port — one signed payload
field, one guard before the nonce, one rejection reason — but the file paths,
and whether `required_profile_async` is reachable in-process at all, are not.
If the port is the target, the propose-time lookup becomes an HTTP call to the
CipherWeave MCP endpoint and the fail-secure default has to be implemented at
that call site instead of inherited from the client; everything downstream of
the token field is identical.
