# RERG assessment and separate host acquisition

This is an additive standalone local Python library/CLI and skill-source
milestone, not default/consumer cutover, semantic/runtime/portability proof, or
product completion. Invoke an assessment only after an independently
authorized host has completed capture. Python imports use `rerg`. The ordinary
proposal/capture CLI is `python3 -m rerg.assessment_cli` (console script
`rerg-assess`): stdin is exactly `{"proposal": ..., "capture": ...}`, and it
returns the full canonical result without a bounded projection or
`PROJECTION_TOO_LARGE` envelope. The unchanged ordinary Python API is
`evaluate_proposal(proposal, capture)`; `canonical_result_bytes` and
`render_assessment_markdown` serialize/render that result. These are equal
interfaces, not fallback evaluators. The separate `python3 -m rerg` and
`python3 -m rerg.raw_cli` entrypoints accept `rerg-foundation/3` JSON on stdin
for the already-compiled low-level contract.

Copied `schemas/rerg` assets and legacy fixtures are provenance/historical
reference, not authoritative `rerg-foundation/3` schemas. The current structural
schemas are `rerg.raw_derivation.INVOCATION_SCHEMA` and
`rerg.raw_derivation.ASSESSMENT_SCHEMA`. The eight declared `rerg/*.py`
component identities remain byte-for-byte unchanged; the new
`rerg/assessment_cli.py` transport is outside that component list. Replay binds
compiled input and result only, not wrapper-code authenticity; no upgraded
replay closure is claimed. Neither this milestone nor synthetic fixtures
close real-target, portability, behavioral-campaign, replay-authentication, or
adoption evidence gates. No document or packet authorizes retrieval, execution,
implementation or release.
The historical `/2` assessment, map, rank/Pareto and first-winner recipe APIs are
retired without translation; `/2` appears only in exact historical code or
artifacts, never as a current alias.

## Ownership and claim boundary

Agent: investigate best-effort, propose source-cited needs and approaches, and
state checkable byte requirements plus unresolved obligations. The agent never
declares support, eligibility, ranking, or semantic proof. Host: grant and
capture a finite scope through authorized tools, owning credentials, retrieval,
capture, provenance, currentness, and effects. RERG: compile the proposal and
capture into the closed foundation contract, evaluate three fixed byte
predicates, determine states/outcomes/reasons/gaps, and retain unranked
survivors. Controller/human: decide and separately authorize any action. No host
acquisition or receipt-ranking helper is reachable from the assessment path.
The assessment is about HOW proposed approaches meet declared byte-checkable
needs, not WHY a candidate or need is worthwhile; it never selects a winner.

## Actor, host, and intended operator workflow

This local GJC skill artifact guides an agent through the reusable deterministic
Python library or CLI; it is not installed or coupled to a host command. The
invoking agent is the workflow orchestrator: it interprets the request, carries
forward a controller-declared target and view, or proposes one when the request
uniquely implies it; ambiguity or disagreement returns to the controller. The
host is the authorized execution boundary around the agent and binds the exact
target and scope under the grant. It owns permissions, credentials, retrieval,
model/network access, process control, effects, capture, provenance, currentness,
persistence and retention. Any adapter recognizes target-specific evidence and
emits portable facts without conclusions. RERG admits, evaluates, closes,
validates and serializes only supplied evidence; it does not authenticate host
attestations. The controller/human owns material meaning, implementation,
adoption, publication and mutation.

1. Receive the candidate, question and intended target context.
2. Investigate available material best-effort; propose needs, approaches, and
   checkable byte requirements, marking unresolved obligations instead of
   asserting semantic conclusions.
3. Carry forward or propose one requested target and evidence view; have the
   controller resolve ambiguity or disagreement.
4. Have the host bind the independently captured target and scope under its
   grant for the bounded, permitted operation.
5. Capture target evidence and provenance through the host, preserving failures
   and limits. Capture production is a host responsibility, not part of the
   assessment library or CLI.
6. Select exactly one equal ordinary assessment surface and invoke it once:
   `evaluate_proposal(proposal, capture)` from `rerg`, or
   `python3 -m rerg.assessment_cli` / `rerg-assess` with exactly
   `{"proposal": ..., "capture": ...}` on stdin. The CLI returns the full
   canonical result; it is not a fallback for the Python API, or vice versa.
7. RERG compiles the two records to the current foundation contract, evaluates
   every applicable byte requirement, and determines states, outcomes, reasons,
   gaps, and unranked survivors.
8. Validate and serialize the supported non-authorizing result, preserving
   reasons and gaps without ranking a winner.
9. Have the controller/human interpret significance and decide whether more facts
   are needed.
10. Require separate exact human/controller authority for implementation,
    adoption, publication or mutation.

This workflow is orchestration guidance, not a new schema or authority lane; the
ordinary proposal/capture interfaces and closed `rerg-foundation/3` contract
remain controlling. The separate `python3 -m rerg` and
`python3 -m rerg.raw_cli` CLIs consume compiled `rerg-foundation/3` JSON, not the
proposal/capture request, and are not alternate evaluator calls in this
workflow. The request's `proposal.target` and captured `capture.target` are
independent declarations.

For an already authorized, bounded local installed-runtime assessment that
contains ordinary machine paths, the host explicitly sets
`capture.host.local_path_policy` to exactly
`local_only_not_portable_or_publication_safe` before the one evaluator call.
This is a caller-supplied handling declaration, not host verification or
authentication; absence of the signal does not prove the data is portable or
publication-safe.
Absent that signal, existing strict path behavior remains. With it, preserve
original path text unchanged only in `proposal.target.harness`,
`capture.target.harness`, `capture.artifacts[*].source_identity`, and
`capture.artifacts[*].data`; do not substitute or redact a path merely because
it is absolute. Keep evidence bytes, source hashes, target identities, and
citation byte spans unchanged. Secrets remain unconditionally rejected. Capture
configuration or code only through existing bounded supported adapter
surfaces; otherwise mark it unknown without expanding those surfaces. The
signal is only a handling limitation, not authority or publication approval.

A neutral contract, explicitly synthetic mechanics fixtures and actual native
records are different evidence classes. Native-record mapping remains open.
`host_attested_unverified` is not authentication; a self-consistent false source
or component declaration is not detectable by this API. Source support proves
neither semantic relevance, future behavior, target activation nor portability.

## Current high-level request and foundation contract

The ordinary proposal/capture root has exactly `proposal` and `capture`, and
`proposal.contract` is exactly `rerg-assessment-request/1`. The Python API and
proposal/capture CLI expose the same evaluation without fallback or dual
dispatch. RERG compiles these records with the independently supplied capture
into the sole current low-level `rerg-foundation/3` representation; the two
raw foundation CLI entrypoints accept that compiled representation directly.

The agent proposal contains:

- `candidate:{key,source_kind,locator,question,citations}`.
- `target:{key,harness,version,surface,configuration_digest}`.
- `needs:[{key,statement,citations,load_bearing,current_requirements}]`.
- `approaches:[{key,coverage,lift,mechanism,required_changes,constraints,
  dependencies,risks,unknowns,validation,reversibility,stop_conditions}]`.

Narrative citations are byte spans, not quotes. A requirement is only
`source_present`, `source_equals` (with `expected`), or `source_same`; all three
are checkable against supplied bytes. Coverage has `unresolved` for an explicit
unknown. A missing coverage row is compiled to the fixed marker
`Missing requirement declaration.`; it is not silently treated as support.
Load-bearing current requirements admit an explicit empty list, compiling to
empty current relations. An explicit empty list does not prove current
sufficiency: an independently supported proposed route remains eligible, never
`no_change`. Explicit empty or null coverage for a load-bearing need is admitted
only with a valid nonempty unresolved obligation; otherwise it remains invalid.
Omitted coverage still compiles to the fixed marker above. Optional needs
may retain an unresolved obligation without omitting the approach. The agent
proposes these facts and obligations but never claims support, eligibility,
semantic proof, ranking, or a winner.

The capture contains an independent `target`, `view`, `host`, `artifacts`, and
exactly eight core `components`. Host owns the grant, credentials, retrieval,
capture, provenance and effects. The host target and requested target each carry
one of exactly three independent surfaces: `installed_runtime`,
`repository_snapshot`, or `other_source`. `repository_snapshot` is never
silently treated as `installed_runtime` proof. Synthetic capture is explicit
(`origin:"synthetic"`, `syn:` IDs); examples in this document are synthetic
data, not a real capture. Static producer identity/version and source hashes are
preserved declarations, not semantic or runtime observations.

All keys are 1–24 ASCII bytes with exact case and
`[A-Za-z0-9._:-]`; IDs are generated without lossy conversion. The generated
low-level IDs use `ca:`, `t:`, `v:`, `r:`, `d:`, `n:`, `p:`, `a:`/`syn:a:`,
`ci:00` and `re:00` forms. No caller-supplied quote, rank, result, winner, or
satisfied claim is accepted.

### Requiredness, gaps, and bounds

Candidate and narrative citations are optional provenance. Citations on
load-bearing needs, declared current requirements, and approach coverage are
required when supplied and remain checkable; non-load-bearing provenance remains
visible but does not become a requirement. Every missing or unusable declared
reference is retained as a field-located gap with its required/optional impact.
The fixed missing-coverage marker above is distinct from an unknown source span.
Unknown artifact spans reserve a citation/relation identity but never fabricate a
hash or artifact record.

Input is bounded to 1,048,576 canonical bytes and depth 32; artifacts carry at
most 4,096 decoded bytes, with 64 spans/relations, four needs, eight approaches,
eight view descriptors/root IDs, and exactly eight components. Each narrative
is at most 512 canonical JSON bytes and each citation/requirement set is at most
eight entries. The complete combined gap bound is 968 records. Complete
canonical JSON is bounded at 1,420,081 bytes, escaped Markdown at 8,520,529
bytes, and invalid-invocation JSON at 2,846 bytes. These are accounting bounds,
not proof of native-shape adequacy.

## Tagged scopes, outcomes and complete output

RERG determines states, outcomes, reasons, gaps, and the complete unranked
survivor set. Global reason scope is exactly `{"kind":"global"}` and route-local
scope is `{"kind":"approach","id":"<approach-id>"}`; a literal approach ID
`global` remains distinct. Preserve contradictory reasons and all applicable
scopes. All five outcomes remain `eligible`, `no_change`, `defer`, `reject`, and
`needs_more_facts`, each exiting 0. Invalid input exits 2 with bounded
diagnostic paths; internal failure exits 1 with exactly `RERG_INTERNAL_ERROR\n`
on stderr. Every result is `authorizing:false` and `can_execute:false`.

```python
# high-level-assessment
from rerg import evaluate_proposal, canonical_result_bytes, render_assessment_markdown

# proposal/capture are already authorized, sanitized in-memory records.
result = evaluate_proposal(proposal, capture)
canonical_packet = canonical_result_bytes(result)
answer = render_assessment_markdown(result)
```

The proposal/capture Python API and CLI are equal full-result interfaces.
`python3 -m rerg.assessment_cli` (or `rerg-assess`) reads exactly the
`{proposal,capture}` root and returns the full canonical result, not a bounded
projection or overflow envelope. `canonical_result_bytes` returns the complete
canonical serialization. `render_assessment_markdown` renders the full result,
including any artifact payload; it is not a payload- or secret-redaction
mechanism. The wrapper does not acquire evidence or perform capture. The separate
`python3 -m rerg` / `python3 -m rerg.raw_cli` entrypoints and
`evaluate_assessment(invocation)` accept the compiled low-level contract; they
are not fallbacks for proposal/capture evaluation. Replay binds compiled input
and result only, not historical execution, authenticated capture, or wrapper
code. Publication validates recorded states, obligations, reason algebra,
gaps, and complete survivors without acquiring more evidence or running a
second assessment.

Keep the exact original canonical UTF-8 length and SHA-256 with the full result.
Present a clearly labeled non-canonical presentation that excludes raw artifact
payloads and secrets while preserving all reasons and scopes, outcomes,
unranked survivors, target/capture and evidence identities, citations and byte
spans, source hashes, gaps/unknowns, validation, reversibility, stop conditions,
and `authorizing:false` / `can_execute:false`. Preserve the original canonical
length and SHA-256 in that display; do not call it a complete or canonical
serialization. If host transport cannot preserve every required field, stop
explicitly and do not claim completeness. Do not retry, spill, truncate as
complete, or invent an overflow/projection protocol.

When `result['input']['host']['local_path_policy']` is present (the
`input.host.local_path_policy` field), always state the local-only,
not-portable, not-publication-safe handling warning. This signal is not
authority, host verification, or authentication. Do not persist results or log
proposal/capture records, artifact bytes, canonical bytes, exception text, or
result content.

## Retained host-only acquisition and bounded followup

`adapt_repository_target` still owns approved filesystem collection and returns
its own receipt/passages/failures. `_validate_adapter_receipt` and its timestamp,
root, inventory, no-follow, parser, accounting and lexical-ranking helpers remain
host-only. Their receipt is not a source invocation and is never implicitly
converted into authenticated assessment evidence. Preserve all failed/uninspected
surfaces; source screens are not semantic or disclosure review. Synthetic tests
of these boundaries establish no real adoption usefulness.

Name the missing fact and existing need before searching. Select explicit safe
inventory paths and record why; do not silently take the first128 filenames or
infer absence from unsearched scope. The following existing recipe requires a
separately authorized Python cell with an externally enforced30-second timeout.
If the facility or confinement is unavailable, stop; do not install a new host
facility. An interruption produces no usable result and no automatic retry.

```python
# bounded-followup-search
import hashlib
import json
import time
from rerg.git_worktree_inventory import collect_git_worktree_inventory, GitInventoryError
from rerg.repository_target_adapter import (
    _open_bound_root, _read_regular_source, _verify_bound_root,
)
from rerg.path_query import _safe, _followup_eligible_paths


def bounded_literal_search(root_path, receipt, paths, needles, scope_basis):
    deadline = time.monotonic() + 30
    result = {
        "paths": [], "failures": [], "attempts": 0, "bytes": 0,
        "searched_paths": [], "unsearched_count": 0,
        "inventory_sha256": None, "scope_basis_sha256": None,
    }

    def stop(code):
        result["paths"] = []
        result["failures"] = [code]
        if len(json.dumps(result, ensure_ascii=False).encode("utf-8")) > 16_384:
            result["unsearched_count"] += len(result["searched_paths"])
            result["searched_paths"] = []
        return result

    def encoded_size():
        return len(json.dumps(result, ensure_ascii=False).encode("utf-8"))

    if (type(paths) is not list or len(paths) > 128
            or type(needles) is not list or not 1 <= len(needles) <= 4
            or type(scope_basis) is not str or not scope_basis.strip()
            or len(scope_basis) > 4096):
        return stop("SEARCH_SCOPE_LIMIT")
    try:
        literals = [needle.encode("utf-8") for needle in needles if type(needle) is str]
        if len(literals) != len(needles) or any(not value or len(value) > 256 for value in literals):
            return stop("SEARCH_QUERY_LIMIT")
        if any(not _safe(path) or len(path.encode("utf-8")) > 4096
               or any(ord(char) < 32 for char in path) for path in paths):
            return stop("SEARCH_PATH_INVALID")
        if len(set(paths)) != len(paths):
            return stop("SEARCH_PATH_INVALID")
        if "followup" in receipt:
            return stop("SEARCH_LINEAGE")
        eligible = _followup_eligible_paths(receipt)
        result["unsearched_count"] = len(eligible)
        result["inventory_sha256"] = receipt["source_binding"]["inventory_sha256"]
        result["scope_basis_sha256"] = hashlib.sha256(scope_basis.encode("utf-8")).hexdigest()
        if not set(paths) <= eligible:
            return stop("SEARCH_SCOPE_EXCLUDED")
    except (KeyError, TypeError, ValueError, UnicodeError):
        return stop("SEARCH_SCOPE_INVALID")
    handle = None
    try:
        if time.monotonic() >= deadline:
            return stop("SEARCH_DEADLINE")
        handle = _open_bound_root(root_path)
        _verify_bound_root(handle)
        if collect_git_worktree_inventory(handle.path) != receipt["inventory"]:
            return stop("SEARCH_BINDING_CHANGED")
        _verify_bound_root(handle)
        for path in paths:
            if time.monotonic() >= deadline:
                return stop("SEARCH_DEADLINE")
            remaining = 8_388_608 - result["bytes"]
            if not remaining:
                return stop("SEARCH_BYTE_LIMIT")
            result["attempts"] += 1
            try:
                data = _read_regular_source(handle, path, remaining)["data"]
            except (OSError, ValueError):
                # A failed read can have consumed bytes. Charge the entire
                # remaining allowance and stop, never retry or count it as zero.
                result["bytes"] += remaining
                return stop("SEARCH_READ_FAILED")
            result["bytes"] += len(data)
            result["searched_paths"].append(path)
            result["unsearched_count"] -= 1
            if time.monotonic() >= deadline:
                return stop("SEARCH_DEADLINE")
            if any(needle in data for needle in literals):
                result["paths"].append(path)
                if len(result["paths"]) > 4:
                    return stop("SEARCH_HIT_LIMIT")
            if encoded_size() > 16_384:
                result["searched_paths"] = []
                result["unsearched_count"] = len(eligible)
                return stop("SEARCH_OUTPUT_LIMIT")
        _verify_bound_root(handle)
        if collect_git_worktree_inventory(handle.path) != receipt["inventory"]:
            return stop("SEARCH_BINDING_CHANGED")
        _verify_bound_root(handle)
        if time.monotonic() >= deadline:
            return stop("SEARCH_DEADLINE")
    except (OSError, ValueError, GitInventoryError):
        return stop("SEARCH_BINDING_FAILED")
    finally:
        if handle is not None:
            try:
                handle.close()
            except (OSError, ValueError):
                stop("SEARCH_CLEANUP_FAILED")
    return result

# In this same timeout=30 cell, using already authorized in-memory inputs:
# leads = bounded_literal_search(authorized_root, collected["receipt"],
#                               explicit_scope, literal_needles, scope_basis)
# print(json.dumps(leads, ensure_ascii=False))
```

Limits remain four literal queries of256 UTF-8 bytes,128 explicit attempts,
8MiB charged read bytes,30seconds and16KiB output. Failed reads charge the entire
remaining allowance because consumed bytes are unknown. Empty scope is no
source evidence; hits are leads, not support. No regex, recursive fallback,
raw excerpts, new store or automatic retry is added. No-follow descriptors and
binding rechecks retain their documented swap-and-restore race limitation.

A successful lead may enter the same adapter with original context/question and
`followup={"prior_receipt": collected["receipt"], "missing_fact": missing_fact,
"need_ids": affected_need_ids, "paths": leads["paths"]}`. At most four additional
files and1MiB aggregate are admitted; no extra discovery seeds. Preserve the
prior timestamp/binding/source bytes, final coherent recapture and every failure.
A followup-bearing prior receipt is rejected. This is one followup per receipt
lineage, not persistent anti-replay protection across copies or process restarts.
Additional-source failures do not support a source claim; binding-wide failures
remain global. Explicit normalization and human authority are separate work.

## Verification and remaining boundaries

Use only an approved external CPython3.12/x86_64/Linux dependency environment,
with the exact parser lock and approved pytest. Provisioning needs separate
permission; this workflow never installs or weakens the lock. Before each
approved focused/full `tests/rerg` launch, the controller must bind candidate
HEAD/diff, actual interpreter/dependency paths/hashes, fresh external temp and
exact environment, then accept a fresh R3 import-origin canary. Failed or unsafe
origin means zero pytest launches. Keep source/dependencies read-only during
execution, allow only approved temporary host-test effects, preserve full streams
and exact tested hashes externally, and verify original main/retained bytes.

Stop on material meaning, baseline/scope drift, unsafe origin/effects or recurring
invariant failure; never lower an assertion, add a second evaluator or hide a
failure as evidence insufficiency. Real Prewalk × GJC/native evidence, full
relation coverage/replay closure, bounded real2×2, consumer/default cutover,
destructive cleanup, adoption/publication/release each remain separate gates.
